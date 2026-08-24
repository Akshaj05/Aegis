// Hand-written recursive-descent parser for SafeShell's restricted shell
// command grammar: simple commands, quoting, pipelines, redirection,
// sequencing, and environment variable expansion.

use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg(pub String);

impl Arg {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectionKind {

    Truncate,

    Append,

    Input,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirection {
    pub kind: RedirectionKind,

    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub name: String,
    pub args: Vec<Arg>,
    pub redirections: Vec<Redirection>,
    pub pipeline_next: Option<Box<ParsedCommand>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {

    And,

    Sequence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {

    pub segments: Vec<(ParsedCommand, Option<Connector>)>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("empty command")]
    EmptyInput,
    #[error("unterminated {0} quote")]
    UnterminatedQuote(&'static str),
    #[error("unsupported construct: {construct} (at position {position}) — SafeShell does not implement a general shell; this syntax is not translated or approximated")]
    UnsupportedConstruct {
        construct: &'static str,
        position: usize,
    },
    #[error("expected a command before `{0}`")]
    ExpectedCommandBefore(String),
    #[error("expected a single word as the redirection target after `{operator}`")]
    RedirectionMissingTarget { operator: &'static str },
    #[error("expected a command after `{connector}`")]
    ExpectedCommandAfter { connector: &'static str },
    #[error("unknown environment variable syntax at position {0}")]
    BadVariableSyntax(usize),
}

pub fn parse_line(input: &str, env: &HashMap<String, String>) -> Result<CommandLine, ParseError> {
    let tokens = tokenize(input, env)?;
    if tokens.is_empty() {
        return Err(ParseError::EmptyInput);
    }
    build_command_line(&tokens)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Pipe,
    Redirect(RedirectionKind),
    And,
    Semicolon,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Word(w) => write!(f, "{w}"),
            Token::Pipe => write!(f, "|"),
            Token::Redirect(RedirectionKind::Truncate) => write!(f, ">"),
            Token::Redirect(RedirectionKind::Append) => write!(f, ">>"),
            Token::Redirect(RedirectionKind::Input) => write!(f, "<"),
            Token::And => write!(f, "&&"),
            Token::Semicolon => write!(f, ";"),
        }
    }
}

fn tokenize(input: &str, env: &HashMap<String, String>) -> Result<Vec<Token>, ParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut tokens = Vec::new();

    while i < chars.len() {
        let c = chars[i];

        if c.is_whitespace() {
            i += 1;
            continue;
        }

        if c == '<' && chars.get(i + 1) == Some(&'<') {
            return Err(ParseError::UnsupportedConstruct {
                construct: "here-document (<<)",
                position: i,
            });
        }
        if (c == '<' || c == '>') && chars.get(i + 1) == Some(&'(') {
            return Err(ParseError::UnsupportedConstruct {
                construct: "process substitution",
                position: i,
            });
        }
        if c == '`' {
            return Err(ParseError::UnsupportedConstruct {
                construct: "backtick command substitution",
                position: i,
            });
        }
        if c == '$' && chars.get(i + 1) == Some(&'(') {
            return Err(ParseError::UnsupportedConstruct {
                construct: "$(...) command substitution",
                position: i,
            });
        }

        match c {
            '|' => {
                tokens.push(Token::Pipe);
                i += 1;
            }
            ';' => {
                tokens.push(Token::Semicolon);
                i += 1;
            }
            '&' => {
                if chars.get(i + 1) == Some(&'&') {
                    tokens.push(Token::And);
                    i += 2;
                } else {
                    return Err(ParseError::UnsupportedConstruct {
                        construct: "background job (&)",
                        position: i,
                    });
                }
            }
            '>' => {
                if chars.get(i + 1) == Some(&'>') {
                    tokens.push(Token::Redirect(RedirectionKind::Append));
                    i += 2;
                } else {
                    tokens.push(Token::Redirect(RedirectionKind::Truncate));
                    i += 1;
                }
            }
            '<' => {
                tokens.push(Token::Redirect(RedirectionKind::Input));
                i += 1;
            }
            _ => {
                let (word, consumed) = scan_word(&chars[i..], env)?;
                tokens.push(Token::Word(word));
                i += consumed;
            }
        }
    }

    Ok(tokens)
}

fn scan_word(chars: &[char], env: &HashMap<String, String>) -> Result<(String, usize), ParseError> {
    let mut out = String::new();
    let mut i = 0usize;

    while let Some(&c) = chars.get(i) {
        if is_word_boundary(c) {
            break;
        }

        match c {
            '\'' => {
                i += 1;
                let start = i;
                while chars.get(i) != Some(&'\'') {
                    if i >= chars.len() {
                        return Err(ParseError::UnterminatedQuote("single"));
                    }
                    i += 1;
                }
                out.push_str(&chars[start..i].iter().collect::<String>());
                i += 1;
            }
            '"' => {
                i += 1;
                loop {
                    match chars.get(i) {
                        None => return Err(ParseError::UnterminatedQuote("double")),
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some('\\')
                            if matches!(chars.get(i + 1), Some('"') | Some('\\') | Some('$')) =>
                        {
                            out.push(chars[i + 1]);
                            i += 2;
                        }
                        Some('`') => {
                            return Err(ParseError::UnsupportedConstruct {
                                construct: "backtick command substitution",
                                position: i,
                            });
                        }
                        Some('$') if chars.get(i + 1) == Some(&'(') => {
                            return Err(ParseError::UnsupportedConstruct {
                                construct: "$(...) command substitution",
                                position: i,
                            });
                        }
                        Some('$') => {
                            let (expanded, consumed) = expand_variable(&chars[i..], env)?;
                            out.push_str(&expanded);
                            i += consumed;
                        }
                        Some(&other) => {
                            out.push(other);
                            i += 1;
                        }
                    }
                }
            }
            '\\' => {
                match chars.get(i + 1) {
                    Some(&next) => {
                        out.push(next);
                        i += 2;
                    }
                    None => {

                        out.push('\\');
                        i += 1;
                    }
                }
            }
            '$' => {
                let (expanded, consumed) = expand_variable(&chars[i..], env)?;
                out.push_str(&expanded);
                i += consumed;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }

    Ok((out, i))
}

fn is_word_boundary(c: char) -> bool {
    c.is_whitespace() || matches!(c, '|' | '>' | '<' | ';' | '&')
}

fn expand_variable(
    chars: &[char],
    env: &HashMap<String, String>,
) -> Result<(String, usize), ParseError> {
    debug_assert_eq!(chars[0], '$');

    if chars.get(1) == Some(&'{') {
        let mut j = 2;
        while chars.get(j) != Some(&'}') {
            if j >= chars.len() {
                return Err(ParseError::BadVariableSyntax(0));
            }
            j += 1;
        }
        let name: String = chars[2..j].iter().collect();
        let value = env.get(&name).cloned().unwrap_or_default();
        Ok((value, j + 1))
    } else {
        let mut j = 1;
        while let Some(&c) = chars.get(j) {
            if c.is_alphanumeric() || c == '_' {
                j += 1;
            } else {
                break;
            }
        }
        if j == 1 {

            return Ok(("$".to_string(), 1));
        }
        let name: String = chars[1..j].iter().collect();
        let value = env.get(&name).cloned().unwrap_or_default();
        Ok((value, j))
    }
}

fn build_command_line(tokens: &[Token]) -> Result<CommandLine, ParseError> {
    let mut segments = Vec::new();
    let mut start = 0usize;

    for idx in 0..tokens.len() {
        let connector = match &tokens[idx] {
            Token::And => Some(Connector::And),
            Token::Semicolon => Some(Connector::Sequence),
            _ => None,
        };
        if let Some(connector) = connector {
            let pipeline = build_pipeline(&tokens[start..idx])?;
            segments.push((pipeline, Some(connector)));
            start = idx + 1;
        }
    }

    if start > tokens.len() {

        unreachable!();
    }
    if start == tokens.len() {
        let connector_name = match tokens.last() {
            Some(Token::And) => "&&",
            Some(Token::Semicolon) => ";",
            _ => unreachable!("start == len only reached via a connector token"),
        };
        return Err(ParseError::ExpectedCommandAfter {
            connector: connector_name,
        });
    }

    let pipeline = build_pipeline(&tokens[start..])?;
    segments.push((pipeline, None));

    Ok(CommandLine { segments })
}

fn build_pipeline(tokens: &[Token]) -> Result<ParsedCommand, ParseError> {
    let stages: Vec<&[Token]> = split_on_pipe(tokens);
    if stages.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    let mut commands = Vec::with_capacity(stages.len());
    for stage in &stages {
        commands.push(build_simple_command(stage)?);
    }

    let mut iter = commands.into_iter().rev();
    let mut current = iter.next().expect("at least one stage");
    for mut earlier in iter {
        earlier.pipeline_next = Some(Box::new(current));
        current = earlier;
    }
    Ok(current)
}

fn split_on_pipe(tokens: &[Token]) -> Vec<&[Token]> {
    let mut stages = Vec::new();
    let mut start = 0usize;
    for (idx, tok) in tokens.iter().enumerate() {
        if *tok == Token::Pipe {
            stages.push(&tokens[start..idx]);
            start = idx + 1;
        }
    }
    stages.push(&tokens[start..]);
    stages
}

fn build_simple_command(tokens: &[Token]) -> Result<ParsedCommand, ParseError> {
    let mut words: Vec<String> = Vec::new();
    let mut redirections: Vec<Redirection> = Vec::new();

    let mut i = 0usize;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Word(w) => {
                words.push(w.clone());
                i += 1;
            }
            Token::Redirect(kind) => {
                let operator = match kind {
                    RedirectionKind::Truncate => ">",
                    RedirectionKind::Append => ">>",
                    RedirectionKind::Input => "<",
                };
                match tokens.get(i + 1) {
                    Some(Token::Word(target)) => {
                        redirections.push(Redirection {
                            kind: *kind,
                            target: target.clone(),
                        });
                        i += 2;
                    }
                    _ => return Err(ParseError::RedirectionMissingTarget { operator }),
                }
            }
            Token::Pipe => unreachable!("pipe already split out by build_pipeline"),
            Token::And | Token::Semicolon => {
                unreachable!("connectors already split out by build_command_line")
            }
        }
    }

    if words.is_empty() {
        let bad_token = tokens.first().map(|t| t.to_string()).unwrap_or_default();
        return Err(ParseError::ExpectedCommandBefore(bad_token));
    }

    let name = words.remove(0);
    let args = words.into_iter().map(Arg).collect();

    Ok(ParsedCommand {
        name,
        args,
        redirections,
        pipeline_next: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parses_simple_command_with_args() {
        let line = parse_line("ls -la /project", &env(&[])).unwrap();
        assert_eq!(line.segments.len(), 1);
        let (cmd, connector) = &line.segments[0];
        assert_eq!(cmd.name, "ls");
        assert_eq!(cmd.args, vec![Arg("-la".into()), Arg("/project".into())]);
        assert!(connector.is_none());
        assert!(cmd.pipeline_next.is_none());
    }

    #[test]
    fn single_quotes_suppress_expansion() {
        let line = parse_line("echo '$HOME'", &env(&[("HOME", "/home/u")])).unwrap();
        let (cmd, _) = &line.segments[0];
        assert_eq!(cmd.args, vec![Arg("$HOME".into())]);
    }

    #[test]
    fn double_quotes_allow_expansion() {
        let line = parse_line("echo \"home is $HOME\"", &env(&[("HOME", "/home/u")])).unwrap();
        let (cmd, _) = &line.segments[0];
        assert_eq!(cmd.args, vec![Arg("home is /home/u".into())]);
    }

    #[test]
    fn unquoted_expansion_with_braces() {
        let line = parse_line("echo ${HOME}/x", &env(&[("HOME", "/home/u")])).unwrap();
        let (cmd, _) = &line.segments[0];
        assert_eq!(cmd.args, vec![Arg("/home/u/x".into())]);
    }

    #[test]
    fn unset_variable_expands_to_empty_string() {
        let line = parse_line("echo [$UNSET]", &env(&[])).unwrap();
        let (cmd, _) = &line.segments[0];
        assert_eq!(cmd.args, vec![Arg("[]".into())]);
    }

    #[test]
    fn parses_pipeline() {
        let line = parse_line("cat file.txt | grep foo | wc -l", &env(&[])).unwrap();
        let (cmd, _) = &line.segments[0];
        assert_eq!(cmd.name, "cat");
        let stage2 = cmd.pipeline_next.as_ref().unwrap();
        assert_eq!(stage2.name, "grep");
        let stage3 = stage2.pipeline_next.as_ref().unwrap();
        assert_eq!(stage3.name, "wc");
        assert!(stage3.pipeline_next.is_none());
    }

    #[test]
    fn parses_redirection() {
        let line = parse_line("echo hi > out.txt", &env(&[])).unwrap();
        let (cmd, _) = &line.segments[0];
        assert_eq!(
            cmd.redirections,
            vec![Redirection {
                kind: RedirectionKind::Truncate,
                target: "out.txt".into()
            }]
        );
    }

    #[test]
    fn parses_append_and_input_redirection() {
        let line = parse_line("cmd >> a.log < in.txt", &env(&[])).unwrap();
        let (cmd, _) = &line.segments[0];
        assert_eq!(
            cmd.redirections,
            vec![
                Redirection {
                    kind: RedirectionKind::Append,
                    target: "a.log".into()
                },
                Redirection {
                    kind: RedirectionKind::Input,
                    target: "in.txt".into()
                },
            ]
        );
    }

    #[test]
    fn parses_sequencing() {
        let line = parse_line("mkdir a; cd a && touch f", &env(&[])).unwrap();
        assert_eq!(line.segments.len(), 3);
        assert_eq!(line.segments[0].0.name, "mkdir");
        assert_eq!(line.segments[0].1, Some(Connector::Sequence));
        assert_eq!(line.segments[1].0.name, "cd");
        assert_eq!(line.segments[1].1, Some(Connector::And));
        assert_eq!(line.segments[2].0.name, "touch");
        assert_eq!(line.segments[2].1, None);
    }

    #[test]
    fn rejects_command_substitution_dollar_paren() {
        let err = parse_line("echo $(whoami)", &env(&[])).unwrap_err();
        assert!(matches!(
            err,
            ParseError::UnsupportedConstruct {
                construct: "$(...) command substitution",
                ..
            }
        ));
    }

    #[test]
    fn rejects_backtick_substitution() {
        let err = parse_line("echo `whoami`", &env(&[])).unwrap_err();
        assert!(matches!(
            err,
            ParseError::UnsupportedConstruct {
                construct: "backtick command substitution",
                ..
            }
        ));
    }

    #[test]
    fn rejects_background_job() {
        let err = parse_line("sleep 5 &", &env(&[])).unwrap_err();
        assert!(matches!(
            err,
            ParseError::UnsupportedConstruct {
                construct: "background job (&)",
                ..
            }
        ));
    }

    #[test]
    fn rejects_heredoc() {
        let err = parse_line("cat << EOF", &env(&[])).unwrap_err();
        assert!(matches!(
            err,
            ParseError::UnsupportedConstruct {
                construct: "here-document (<<)",
                ..
            }
        ));
    }

    #[test]
    fn rejects_process_substitution() {
        let err = parse_line("diff <(ls a) <(ls b)", &env(&[])).unwrap_err();
        assert!(matches!(
            err,
            ParseError::UnsupportedConstruct {
                construct: "process substitution",
                ..
            }
        ));
    }

    #[test]
    fn rejects_unterminated_single_quote() {
        let err = parse_line("echo 'unterminated", &env(&[])).unwrap_err();
        assert_eq!(err, ParseError::UnterminatedQuote("single"));
    }

    #[test]
    fn rejects_unterminated_double_quote() {
        let err = parse_line("echo \"unterminated", &env(&[])).unwrap_err();
        assert_eq!(err, ParseError::UnterminatedQuote("double"));
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(
            parse_line("", &env(&[])).unwrap_err(),
            ParseError::EmptyInput
        );
        assert_eq!(
            parse_line("   ", &env(&[])).unwrap_err(),
            ParseError::EmptyInput
        );
    }

    #[test]
    fn rejects_dangling_pipe() {
        let err = parse_line("ls |", &env(&[])).unwrap_err();
        assert!(matches!(err, ParseError::ExpectedCommandBefore(_)));
    }

    #[test]
    fn rejects_dangling_connector() {
        let err = parse_line("ls &&", &env(&[])).unwrap_err();
        assert_eq!(err, ParseError::ExpectedCommandAfter { connector: "&&" });
    }

    #[test]
    fn rejects_redirection_missing_target() {
        let err = parse_line("ls >", &env(&[])).unwrap_err();
        assert_eq!(err, ParseError::RedirectionMissingTarget { operator: ">" });
    }

    #[test]
    fn backslash_escapes_a_space_in_unquoted_word() {
        let line = parse_line("touch foo\\ bar", &env(&[])).unwrap();
        let (cmd, _) = &line.segments[0];
        assert_eq!(cmd.args, vec![Arg("foo bar".into())]);
    }
}
