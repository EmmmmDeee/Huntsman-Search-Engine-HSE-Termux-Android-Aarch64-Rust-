- `serve` reads a file upload to `/api/inspect` as exactly its `Content-Length`: bytes a client
  sends after it no longer make it look short, and an upload that is streaming its body is busy,
  so a full server making room closes an idle connection, never the one sending a file. The file
  and the one inspection place are freed once the answer is built, so a client that reads its
  answer slowly holds neither. A head the client stopped part way through is answered `400`, not
  `503` "an inspection is already running".
- `serve` refuses a request with a `Transfer-Encoding` on every route: it reads bodies by
  `Content-Length` only, and a chunked upload was handed over as the file with its framing. A
  `HEAD` answer is the `GET` answer's head alone on every route; the JSON routes sent a body.
