// Shared display-formatting helpers: labels, tones, byte/timestamp
// formatting used across components.
export function categoryLabel(category: string | null): string {
  switch (category) {
    case "safe":
      return "Safe";
    case "dangerous_containable":
      return "Dangerous (contained)";
    case "unsafe_to_contain":
      return "Unsafe to contain";
    default:
      return "Unclassified";
  }
}

export function categoryTone(category: string | null): "safe" | "warn" | "danger" | "neutral" {
  switch (category) {
    case "safe":
      return "safe";
    case "dangerous_containable":
      return "warn";
    case "unsafe_to_contain":
      return "danger";
    default:
      return "neutral";
  }
}

export function riskLabel(risk: string | null): string {
  if (!risk) return "Unrated";
  return risk.charAt(0).toUpperCase() + risk.slice(1);
}

export function riskTone(risk: string | null): "safe" | "warn" | "danger" | "neutral" {
  switch (risk) {
    case "low":
      return "safe";
    case "medium":
      return "warn";
    case "high":
    case "critical":
      return "danger";
    default:
      return "neutral";
  }
}

export function stageLabel(stage: string): string {
  return stage
    .toLowerCase()
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

export function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
