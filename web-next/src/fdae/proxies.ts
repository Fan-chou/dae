import type { Proxy } from '@/types'
import { fetchGroups } from './client'
export async function proxySnapshot(): Promise<{
  proxies: Record<string, Proxy>
}> {
  const groups = await fetchGroups()
  const proxies: Record<string, Proxy> = {}
  const empty = { history: [], extra: {}, icon: '', now: '' }
  for (const group of groups)
    for (const member of group.members || []) {
      proxies[member.name] ??= { ...empty, name: member.name, type: 'fdae' }
    }
  for (const group of groups) {
    proxies[group.name] = {
      ...empty,
      name: group.name,
      type: 'Selector',
      all: group.selection_members?.length
        ? group.selection_members
        : (group.members || []).map((member) => member.name),
      now: group.selected || '',
      selectable: !!group.selectable,
      fdaePolicy: group.policy,
      fdaeAutomatic: !group.selectable,
    }
  }
  return { proxies }
}

// What a group does with its members, in words. The raw policy name stays
// available as the tooltip for anyone who writes the config.
export function policyLabel(policy?: string): string {
  const name = (policy || '').replace(/\(.*\)$/, '')
  return (
    {
      fixed: '手动选择',
      min: '最近延迟最低',
      min_avg10: '近 10 次均值最低',
      min_moving_avg: '滑动均值最低',
      first_alive: '首个可用',
      random: '随机',
      fallback: '故障转移',
      url_test: '自动测速',
    }[name] ?? (policy || '')
  )
}
