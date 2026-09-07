import { useEffect, useState } from "react";

export interface AsyncState<T> {
    data: T | null;
    error: string;
    loading: boolean;
}

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
    const [state, setState] = useState<AsyncState<T>>({
        data: null,
        error: "",
        loading: true,
    });

    useEffect(() => {
        let current = true;
        setState((prev) => ({ ...prev, loading: true }));

        fn()
            .then((data) => {
                if (current) setState({ data, error: "", loading: false });
            })
            .catch((err: unknown) => {
                if (!current) return;
                setState({
                    data: null,
                    error: err instanceof Error ? err.message : "Request failed",
                    loading: false,
                });
            });

        return () => {
            current = false;
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, deps);

    return state;
}
