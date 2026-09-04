/** Associate requests with explicit interactions, not background polling. */
export type ActionState = { id: number; label: string; pending: number; done: boolean; asynchronous: boolean; error: string; changed: () => void };
export type FeedbackMessage = { id: number; label: string; phase: "pending" | "finished" | "error"; detail?: string };
export const FEEDBACK_EVENT = "app:action-feedback";
let current: ActionState | undefined;
let sequence = 0;
export function newAction(label: string, changed: () => void): ActionState {
  return { id: ++sequence, label, pending: 0, done: false, asynchronous: false, error: "", changed };
}
export function withAction<T>(action: ActionState, callback: () => T): T {
  const previous = current; current = action;
  try { return callback(); } finally { current = previous; }
}
export function trackActionRequest() {
  const action = current;
  if (!action) return (_error?: unknown) => {};
  action.pending++; action.asynchronous = true; action.changed();
  return (error?: unknown) => {
    action.pending--;
    if (error) action.error = error instanceof Error ? error.message : String(error);
    action.changed();
  };
}
export function publishFeedback(message: FeedbackMessage) {
  window.dispatchEvent(new CustomEvent(FEEDBACK_EVENT, { detail: message }));
}
