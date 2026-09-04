import React, { createContext, useContext, useEffect, useRef, useState } from "react";
import { FEEDBACK_EVENT, newAction, publishFeedback, withAction, type FeedbackMessage } from "./action-feedback-state";
import "./action-feedback.css";

const FormBusy = createContext(false);
function useActionFeedback() {
  const [busy, setBusy] = useState(false);
  const locked = useRef(false), mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  function run(label: string, callback: () => unknown) {
    if (locked.current) return;
    locked.current = true;
    let finished = false;
    const action = newAction(label, () => {
      if (finished) return;
      const waiting = !action.done || action.pending > 0;
      if (mounted.current) setBusy(waiting && action.asynchronous);
      if (action.asynchronous && waiting) publishFeedback({ id: action.id, label, phase: "pending" });
      if (!waiting) {
        finished = true; locked.current = false;
        if (action.error) publishFeedback({ id: action.id, label, phase: "error", detail: action.error });
        else if (action.asynchronous) publishFeedback({ id: action.id, label, phase: "finished" });
      }
    });
    try {
      const result = withAction(action, callback);
      if (result && typeof (result as PromiseLike<unknown>).then === "function") {
        action.asynchronous = true; action.changed();
        void Promise.resolve(result).catch(error => { action.error = error instanceof Error ? error.message : String(error); }).finally(() => { action.done = true; action.changed(); });
      } else { action.done = true; action.changed(); }
    } catch (error) {
      action.error = error instanceof Error ? error.message : String(error);
      action.done = true; action.changed();
    }
  }
  return { busy, run, locked };
}

export function FeedbackButton({ onClick, disabled, children, ...props }: React.ComponentProps<"button">) {
  const { busy, run, locked } = useActionFeedback();
  const formBusy = useContext(FormBusy);
  const waiting = busy || (formBusy && props.type !== "button");
  const [pressed, setPressed] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  return <button {...props} disabled={disabled || waiting} aria-busy={waiting || props["aria-busy"]} data-feedback-pressed={pressed || undefined} onClick={event => {
    if (locked.current) { event.preventDefault(); return; }
    setPressed(true); clearTimeout(timer.current); timer.current = setTimeout(() => setPressed(false), 450);
    if (onClick) run((props["aria-label"] || event.currentTarget.textContent || "操作").trim().slice(0, 80), () => onClick(event));
  }}>{children}{waiting ? <span className="action-feedback-spinner" aria-hidden="true" /> : null}</button>;
}

export function FeedbackForm({ onSubmit, children, ...props }: React.ComponentProps<"form">) {
  const { busy, run, locked } = useActionFeedback();
  return <FormBusy.Provider value={busy}><form {...props} aria-busy={busy || props["aria-busy"]} onSubmit={event => {
    if (locked.current) { event.preventDefault(); return; }
    if (!onSubmit) return;
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    run((submitter?.textContent || "提交表单").trim().slice(0, 80), () => onSubmit(event));
  }}>{children}</form></FormBusy.Provider>;
}

export function ActionFeedbackViewport() {
  const [message, setMessage] = useState<FeedbackMessage | null>(null);
  const newest = useRef(0);
  useEffect(() => {
    const receive = (event: Event) => {
      const next = (event as CustomEvent<FeedbackMessage>).detail;
      if (next.id < newest.current) return;
      newest.current = next.id; setMessage(next);
    };
    window.addEventListener(FEEDBACK_EVENT, receive);
    return () => window.removeEventListener(FEEDBACK_EVENT, receive);
  }, []);
  useEffect(() => {
    if (!message || message.phase !== "finished") return;
    const timer = setTimeout(() => setMessage(null), 5000);
    return () => clearTimeout(timer);
  }, [message]);
  return <aside className={`action-feedback-toast ${message?.phase ?? "empty"}`} role="status" aria-live="polite" aria-atomic="true">{message && <><div><strong>{message.label}：{message.phase === "pending" ? "处理中…" : message.phase === "error" ? "操作失败" : "操作已结束，请查看页面结果"}</strong>{message.detail && <p>{message.detail}</p>}{message.phase === "pending" && <small>请等待页面结果，不要重复提交。</small>}</div><button type="button" aria-label="关闭操作提示" onClick={() => setMessage(null)}>×</button></>}</aside>;
}
