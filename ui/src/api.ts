import { GraphData } from './types';

export async function runNmapScan(target: string, args: string): Promise<GraphData> {
  const argList = args.trim() ? args.trim().split(/\s+/) : [];
  const res = await fetch('/api/scan/nmap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, args: argList })
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}