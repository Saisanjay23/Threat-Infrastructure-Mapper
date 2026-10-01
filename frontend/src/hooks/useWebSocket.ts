import { useEffect, useRef, useState } from "react";
import { wsUrl } from "@/lib/api";
import type { ProgressMessage } from "@/types/api";

export type WsState = "connecting" | "open" | "closed";

/**
 * Subscribes to a TIM WebSocket stream with automatic reconnect (exponential backoff).
 * `onMessage` is kept in a ref so callers can pass inline closures.
 */
export function useWebSocket(path: string | null, onMessage: (msg: ProgressMessage) => void, enabled = true): WsState {
  const [state, setState] = useState<WsState>("closed");
  const handler = useRef(onMessage);
  handler.current = onMessage;

  useEffect(() => {
    if (!path || !enabled) return;
    let socket: WebSocket | null = null;
    let retry = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let disposed = false;

    const connect = () => {
      setState("connecting");
      socket = new WebSocket(wsUrl(path));
      socket.onopen = () => {
        retry = 0;
        setState("open");
      };
      socket.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as ProgressMessage;
          if (msg.type !== "ping") handler.current(msg);
        } catch {
          /* ignore malformed frames */
        }
      };
      socket.onclose = (ev) => {
        setState("closed");
        if (disposed || ev.code === 4401 || ev.code === 4403 || ev.code === 4404) return;
        retry += 1;
        timer = setTimeout(connect, Math.min(15000, 500 * 2 ** retry));
      };
    };
    connect();
    return () => {
      disposed = true;
      if (timer) clearTimeout(timer);
      socket?.close();
    };
  }, [path, enabled]);

  return state;
}
