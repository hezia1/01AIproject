import React, { Children, cloneElement, isValidElement, useState, type ReactNode } from "react";

import { FeedbackButton } from "./action-feedback";
export const PAGE_SIZE = 10;

export function PageControls({ page, total, onChange }: { page: number; total: number; onChange: (page: number) => void }) {
  const count = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return <span className="pagination" role="navigation" aria-label="列表分页"><span>共 {total} 条 · 每页 10 条 · 第 {page}/{count} 页</span><FeedbackButton className="secondary-action" disabled={page <= 1} onClick={() => onChange(page - 1)}>上一页</FeedbackButton><FeedbackButton className="secondary-action" disabled={page >= count} onClick={() => onChange(page + 1)}>下一页</FeedbackButton></span>;
}

/** Keep row handlers and keys intact; pagination is React state, not DOM hiding. */
export function PagedTable({ children, ...props }: React.TableHTMLAttributes<HTMLTableElement>) {
  const [requested, setPage] = useState(1);
  let total = 0;
  const body = Children.toArray(children).find(child => isValidElement(child) && child.type === "tbody");
  const rows = isValidElement<{ children?: ReactNode }>(body) ? Children.toArray(body.props.children) : [];
  total = rows.length;
  const page = Math.min(requested, Math.max(1, Math.ceil(total / PAGE_SIZE)));
  return <><table {...props}>{Children.map(children, child => {
    if (!isValidElement<{ children?: ReactNode }>(child) || child.type !== "tbody") return child;
    return cloneElement(child, {}, rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE));
  })}</table>{total > PAGE_SIZE ? <PageControls page={page} total={total} onChange={setPage} /> : null}</>;
}

export function PagedItems({ children }: { children: ReactNode }) {
  const [requested, setPage] = useState(1);
  const items = Children.toArray(children);
  const page = Math.min(requested, Math.max(1, Math.ceil(items.length / PAGE_SIZE)));
  const controls = <PageControls page={page} total={items.length} onChange={setPage} />;
  const isList = isValidElement(items[0]) && items[0].type === "li";
  return <>{items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)}{items.length > PAGE_SIZE ? isList ? <li className="pagination-list-item">{controls}</li> : controls : null}</>;
}
