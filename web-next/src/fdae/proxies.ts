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
