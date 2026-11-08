import { useCallback, useEffect, useRef, useState } from "react";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

export function useAsync<T>(
  loader: () => Promise<T>,
  deps: unknown[] = [],
): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);

  const run = useCallback(() => {
    const current = ++generation.current;
    setLoading(true);
    setError(null);
    loader()
      .then((result) => {
        if (generation.current === current) {
          setData(result);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (generation.current === current) {
          setError(err instanceof Error ? err.message : String(err));
          setLoading(false);
        }
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    run();
  }, [run]);

  return { data, loading, error, reload: run };
}
