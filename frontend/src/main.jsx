import { useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'

async function request(path, options = {}) {
  const response = await fetch(path, options)
  const body = await response.json().catch(() => ({ error: response.statusText }))
  if (!response.ok) throw new Error(JSON.stringify(body, null, 2))
  return body
}

function App() {
  const [output, setOutput] = useState('')
  const [preview, setPreview] = useState(null)
  const [job, setJob] = useState(null)
  const [busy, setBusy] = useState(false)
  const [text, setText] = useState('aloha testing from react')
  const poller = useRef(null)

  useEffect(() => () => clearTimeout(poller.current), [])

  const run = async (label, action) => {
    setBusy(true)
    setOutput(label)
    try {
      const result = await action()
      setOutput(JSON.stringify(result, null, 2))
      return result
    } catch (error) {
      setOutput(error.message)
    } finally {
      setBusy(false)
    }
  }

  const previewPosts = () => run('Loading preview...', async () => {
    const result = await request('/delete-all-posts/preview')
    setPreview(result)
    return result
  })

  const pollJob = async (jobId) => {
    try {
      const result = await request(`/api/delete/status/${jobId}`)
      setJob(result)
      setOutput([
        result.message,
        `Progress: ${result.processed}/${result.total ?? '?'}`,
        `Deleted: ${result.deleted} | Failed: ${result.failed}`,
        '',
        ...(result.events || []).slice(-8)
      ].join('\n'))
      if (result.status === 'running') {
        poller.current = setTimeout(() => pollJob(jobId), 1000)
      } else {
        setBusy(false)
      }
    } catch (error) {
      setOutput(error.message)
      setBusy(false)
    }
  }

  const deletePosts = async () => {
    if (!preview?.posts?.length) return
    if (!window.confirm(`Delete all ${preview.posts.length} posts and replies? This cannot be undone.`)) return
    setBusy(true)
    setOutput('Starting deletion job...')
    try {
      const result = await request('/api/delete/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: 'DELETE' })
      })
      await pollJob(result.job_id)
    } catch (error) {
      setOutput(error.message)
      setBusy(false)
    }
  }

  return <main>
    <header>
      <div>
        <p className="eyebrow">X OAuth Bot</p>
        <h1>Account control center</h1>
      </div>
      <button onClick={() => window.location.href = '/authorize'}>Authorize</button>
    </header>

    <section className="card">
      <h2>Account</h2>
      <div className="actions">
        <button disabled={busy} onClick={() => run('Checking account...', () => request('/me'))}>Check account</button>
        <button disabled={busy} onClick={() => run('Refreshing token...', () => request('/refresh', { method: 'POST' }))}>Refresh token</button>
        <button disabled={busy} onClick={() => run('Clearing token...', () => request('/logout', { method: 'POST' }))}>Clear token</button>
      </div>
    </section>

    <section className="card">
      <h2>Post</h2>
      <textarea value={text} onChange={event => setText(event.target.value)} rows="3" />
      <button disabled={busy || !text.trim()} onClick={() => run('Posting...', () => request('/tweet', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text })
      }))}>Post</button>
    </section>

    <section className="card danger-card">
      <h2>Delete posts</h2>
      <p>Preview first. Deletion runs in the backend and updates live every second. Requests wait 4 seconds between X API calls.</p>
      <div className="actions">
        <button disabled={busy} onClick={previewPosts}>Preview my posts</button>
        <button className="danger" disabled={busy || !preview?.posts?.length} onClick={deletePosts}>
          Delete previewed posts
        </button>
      </div>
      {preview && <div className="preview">
        <strong>@{preview.username}: {preview.posts.length} post(s)</strong>
        {preview.posts.map(post => <div className="post" key={post.id}><code>{post.id}</code> {post.text}</div>)}
      </div>}
      {job && <p className="job-state">Job: {job.status}</p>}
    </section>

    <section className="card output-card">
      <h2>Live output</h2>
      <pre>{output || 'Ready.'}</pre>
    </section>
  </main>
}

createRoot(document.getElementById('root')).render(<App />)
