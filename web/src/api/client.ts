import axios, { type AxiosInstance } from "axios";
import type { AdminGroup, AdminLogs, AdminReload, AdminStatus } from "./types";

export class KdaeApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function createClient(baseUrl: string, secret: string): AxiosInstance {
  return axios.create({
    baseURL: baseUrl || undefined,
    timeout: 12000,
    headers: {
      Authorization: "Bearer " + secret,
      "X-Kdae-Authorization": "Bearer " + secret,
    },
  });
}

async function request<T>(client: AxiosInstance, path: string, init?: { method?: string; data?: unknown }): Promise<T> {
  try {
    const response = await client.request<T>({
      url: path,
      method: init?.method || "GET",
      data: init?.data,
    });
    return response.data;
  } catch (err) {
    if (axios.isAxiosError(err)) {
      const body = err.response?.data as { error?: string } | undefined;
      throw new KdaeApiError(err.response?.status || 0, body?.error || err.message);
    }
    throw err;
  }
}

export function fetchStatus(client: AxiosInstance): Promise<AdminStatus> {
  return request(client, "/v1/status");
}

export function fetchGroups(client: AxiosInstance): Promise<{ groups: AdminGroup[] }> {
  return request(client, "/v1/groups");
}

export function putGroupMember(client: AxiosInstance, group: string, member: string): Promise<{ group: string; member: string }> {
  return request(client, "/v1/groups/" + encodeURIComponent(group), {
    method: "PUT",
    data: { member },
  });
}

export function fetchLogs(client: AxiosInstance, n = 300): Promise<AdminLogs> {
  return request(client, "/v1/logs?n=" + encodeURIComponent(String(n)));
}

export function postReload(client: AxiosInstance): Promise<AdminReload> {
  return request(client, "/v1/reload", { method: "POST" });
}
