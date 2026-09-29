"use client";

import { useEffect, useRef, useState } from "react";
import { api, getToken, scanEventsUrl } from "./api";
import type { ScanEvent, ScanSnapshot, Severity } from "./types";

export interface LiveFinding {
  id: string;
  type: string;
  severity: Severity;
  confidence: string;
  title: string;
}

export interface LiveState {
  snapshot: ScanSnapshot | null;
  findings: LiveFinding[];
  connected: boolean;
  error: string | null;
}

// Reconnection model (mirrors the backend): on every (re)connect we first GET the
// authoritative snapshot, then apply deltas on top. A dropped delta is harmless because the
// next reconnect re-fetches the snapshot and reconciles.
export function useScanEvents(scanId: string): LiveState {
  const [snapshot, setSnapshot] = useState<ScanSnapshot | null>(null);
  const [findings, setFindings] = useState<LiveFinding[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const closedByUs = useRef(false);

  useEffect(() => {
    closedByUs.current = false;
    let retry: ReturnType<typeof setTimeout> | undefined;

    // Milestones change DB row counts (subdomains, endpoints, …). Deltas only carry stage
    // progress, so on a stage/scan milestone we re-pull the authoritative snapshot to keep
    // the counters live and correct.
    const refreshSnapshot = async () => {
      try {
        setSnapshot(await api.scanState(scanId));
      } catch {
        /* transient; the next milestone or reconnect will reconcile */
      }
    };

    const applyDelta = (evt: ScanEvent) => {
      switch (evt.type) {
        case "snapshot":
          setSnapshot(evt as unknown as ScanSnapshot);
          break;
        case "scan.status":
          setSnapshot((s) => (s ? { ...s, status: evt.status } : s));
          void refreshSnapshot();
          break;
        case "stage.started":
        case "stage.progress":
        case "stage.done":
          setSnapshot((s) => {
            if (!s) return s;
            const stages = s.stages.map((st) =>
              st.name === evt.stage
                ? {
                    ...st,
                    status:
                      evt.type === "stage.done"
                        ? "done"
                        : evt.type === "stage.started"
                          ? "running"
                          : st.status,
                    done: evt.type === "stage.progress" ? evt.done : st.done,
                    total: evt.type === "stage.progress" ? evt.total : st.total,
                  }
                : st,
            );
            return { ...s, stages };
          });
          if (evt.type === "stage.done") void refreshSnapshot();
          break;
        case "finding.created":
          setFindings((f) => [
            {
              id: evt.finding_id,
              type: evt.finding_type,
              severity: evt.severity,
              confidence: evt.confidence,
              title: evt.title,
            },
            ...f,
          ]);
          break;
        default:
          break; // ping / unknown
      }
    };

    const connect = async () => {
      try {
        const snap = await api.scanState(scanId);
        setSnapshot(snap);
        setError(null);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
      }

      const token = getToken();
      // Token via subprotocol ("bearer.<token>") — never in the URL query string.
      const protocols = token ? ["bearer." + token] : undefined;
      const ws = new WebSocket(scanEventsUrl(scanId), protocols);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onmessage = (m) => {
        try {
          applyDelta(JSON.parse(m.data) as ScanEvent);
        } catch {
          /* ignore malformed frame */
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (!closedByUs.current) retry = setTimeout(connect, 1500); // reconnect + reconcile
      };
      ws.onerror = () => ws.close();
    };

    void connect();
    return () => {
      closedByUs.current = true;
      if (retry) clearTimeout(retry);
      wsRef.current?.close();
    };
  }, [scanId]);

  return { snapshot, findings, connected, error };
}
