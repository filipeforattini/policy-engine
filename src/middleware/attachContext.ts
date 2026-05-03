import type { EvalContext, Principal, RequestLike } from "../engine/types"

export type AttachContextOptions = {
  extractPrincipal: (req: RequestLike) => Principal
  extractContext?: (req: RequestLike) => EvalContext
}

export type NextFn = (err?: unknown) => void

export function createAttachContext(opts: AttachContextOptions) {
  return function attachContext(req: RequestLike, _res: unknown, next: NextFn): void {
    try {
      const principal = opts.extractPrincipal(req)
      const context = opts.extractContext ? opts.extractContext(req) : {}
      req.authz = { principal, context, filtered: {} }
      next()
    } catch {
      req.authz = undefined
      next()
    }
  }
}
