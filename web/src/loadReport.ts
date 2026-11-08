import { ReportError, parseScanReport, type ScanReport } from "./model";

const EMBEDDED_ID = "seethru-report";
const MAX_FILE_BYTES = 20 * 1024 * 1024;

export function readEmbeddedReport(): ScanReport | undefined {
  const element = document.getElementById(EMBEDDED_ID);
  if (!(element instanceof HTMLScriptElement) || element.type !== "application/json") return undefined;
  return parseScanReport(JSON.parse(element.textContent ?? ""));
}

export async function readReportFile(file: File): Promise<ScanReport> {
  if (file.size > MAX_FILE_BYTES) throw new ReportError("file is larger than 20 MB");
  const text = await file.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new ReportError("file is not valid JSON");
  }
  return parseScanReport(json);
}
