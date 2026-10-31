"use client";

import * as React from "react";

import { api } from "@/lib/api";

type ModelListStatus = "idle" | "loading" | "success" | "error";

export function useLLMModels({
  open,
  format,
  baseUrl,
  apiKey,
  proxy,
  profileId,
  hasStoredKey,
}: {
  open: boolean;
  format: string;
  baseUrl: string;
  apiKey: string;
  proxy: string;
  profileId?: number;
  hasStoredKey: boolean;
}) {
  const normalizedBaseUrl = baseUrl.trim();
  const normalizedApiKey = apiKey.trim();
  const normalizedProxy = proxy.trim();
  const request = React.useMemo(
    () => ({ format, baseUrl: normalizedBaseUrl, apiKey: normalizedApiKey, proxy: normalizedProxy, profileId }),
    [format, normalizedBaseUrl, normalizedApiKey, normalizedProxy, profileId],
  );
  const [refreshTick, refresh] = React.useReducer((value: number) => value + 1, 0);
  const [result, setResult] = React.useState<{
    request: typeof request;
    refreshTick: number;
    status: ModelListStatus;
    models: string[];
    error?: string;
  }>();

  let validUrl = normalizedBaseUrl === "";
  if (normalizedBaseUrl) {
    try {
      const url = new URL(normalizedBaseUrl);
      validUrl = url.protocol === "https:" || url.protocol === "http:";
    } catch {
      validUrl = false;
    }
  }
  const canLoad = validUrl && (normalizedBaseUrl !== "" || normalizedApiKey !== "" || hasStoredKey);

  React.useEffect(() => {
    if (!open || !canLoad) {
      setResult(undefined);
      return;
    }
    setResult({ request, refreshTick, status: "loading", models: [] });
    const controller = new AbortController();
    // Wait for typing to settle; changing the endpoint/key or closing cancels the old request.
    const timer = setTimeout(async () => {
      try {
        const response = await api.fetchLLMModels(
          request.format,
          request.baseUrl,
          request.apiKey,
          request.proxy,
          request.profileId,
          controller.signal,
        );
        if (controller.signal.aborted) return;
        const models = [...new Set((response.models ?? []).map((id) => id.trim()).filter(Boolean))].sort();
        setResult({
          request,
          refreshTick,
          status: response.ok ? "success" : "error",
          models: response.ok ? models : [],
          error: response.ok ? undefined : (response.error ?? "未获取到模型列表"),
        });
      } catch (error) {
        if (controller.signal.aborted) return;
        setResult({
          request,
          refreshTick,
          status: "error",
          models: [],
          error: error instanceof Error ? error.message : "请求失败",
        });
      }
    }, 600);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [open, canLoad, request, refreshTick]);

  // Cached results belong only to this form state, including across close/reopen.
  const current =
    open && canLoad && result?.request === request && result.refreshTick === refreshTick ? result : undefined;
  return {
    models: current?.models ?? [],
    status: current?.status ?? (open && canLoad ? "loading" : "idle"),
    error: current?.error,
    invalidUrl: !validUrl,
    canLoad,
    refresh,
  };
}
