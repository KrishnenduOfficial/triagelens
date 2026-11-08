import { fetchMetrics, type MetricQuery, type Metrics } from "../api/apiService";

export interface MetricRequestState {
  query: MetricQuery;
  status: "loading" | "ready" | "error";
  metrics: Metrics | null;
  error: string | null;
}

/** Cleanup and sequence checks work even when a transport ignores cancellation. */
export function createMetricsLoader(fetcher = fetchMetrics) {
  let generation = 0;
  let controller: AbortController | undefined;
  return {
    load(query: MetricQuery, receive: (state: MetricRequestState) => void): () => void {
      controller?.abort();
      const current = ++generation;
      const activeController = new AbortController();
      controller = activeController;
      const active = () => current === generation && !activeController.signal.aborted;
      receive({ query, status: "loading", metrics: null, error: null });
      void (async () => {
        try {
          const metrics = await fetcher(query, activeController.signal);
          if (active()) receive({ query, status: "ready", metrics, error: null });
        } catch (error) {
          if (active()) receive({ query, status: "error", metrics: null,
            error: error instanceof Error ? error.message : "Unable to load metrics." });
        }
      })();
      return () => {
        activeController.abort();
        if (current === generation) ++generation;
      };
    },
  };
}
