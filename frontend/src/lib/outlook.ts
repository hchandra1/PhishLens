/// <reference types="office-js" />

/** The open message's original source, as close to the real .eml as this Outlook allows. */
export async function currentMessageSource(): Promise<Uint8Array | string> {
  const item = Office.context.mailbox.item as Office.MessageRead;
  if (Office.context.requirements.isSetSupported("Mailbox", "1.14")) {
    const base64 = await call<string>((done) => item.getAsFileAsync(done));
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  }
  // Older Outlook: rebuild a message from the internet headers and the HTML body. The
  // sender and link checks still work; attachments are not included.
  const html = await call<string>((done) => item.body.getAsync(Office.CoercionType.Html, done));
  let headers = `From: ${item.from?.displayName ?? ""} <${item.from?.emailAddress ?? ""}>\r\nSubject: ${item.subject ?? ""}`;
  if (Office.context.requirements.isSetSupported("Mailbox", "1.8")) {
    const all = await call<string>((done) => item.getAllInternetHeadersAsync(done));
    headers = withoutBodyHeaders(all);
  }
  return `${headers.trimEnd()}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n${html}`;
}

/** Drop the original MIME structure headers; the rebuilt message has a single HTML body. */
function withoutBodyHeaders(headers: string): string {
  const drop = /^(content-type|content-transfer-encoding|mime-version):/i;
  const kept: string[] = [];
  let skipping = false;
  for (const line of headers.split(/\r?\n/)) {
    if (/^[ \t]/.test(line)) {
      if (!skipping) kept.push(line);
      continue;
    }
    skipping = drop.test(line);
    if (!skipping && line) kept.push(line);
  }
  return kept.join("\r\n");
}

function call<T>(start: (done: (result: Office.AsyncResult<T>) => void) => void): Promise<T> {
  return new Promise((resolve, reject) =>
    start((result) =>
      result.status === Office.AsyncResultStatus.Succeeded
        ? resolve(result.value)
        : reject(new Error(result.error?.message ?? "Outlook couldn't read this message.")),
    ),
  );
}
