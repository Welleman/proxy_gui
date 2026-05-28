import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import asyncio
from urllib.parse import urlparse

LOG_QUEUE = queue.Queue()

def log(msg):
    LOG_QUEUE.put(f"[{threading.current_thread().name}] {msg}")

# ================= PROXY SERVER =================
class ProxyWorker:
    def __init__(self, listen_port):
        self.listen_port = listen_port
        self.loop = None
        self.server = None

    def start(self):
        """Запускается в отдельном потоке"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._run())
        except asyncio.CancelledError:
            pass
        finally:
            self.loop.run_until_complete(self._cleanup())
            self.loop.close()

    async def _run(self):
        # --- Вспомогательная функция пересылки данных ---
        async def forward_bytes(src, dst, label):
            try:
                while True:
                    chunk = await src.read(4096)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            except Exception as e:
                log(f"PROXY | ! Forward error ({label}): {e}")
            finally:
                try:
                    dst.close()
                    await dst.wait_closed()
                except:
                    pass

        # --- Обработчик клиентского соединения ---
        async def handle_client(reader, writer):
            peer = writer.get_extra_info('peername')
            log(f"PROXY | + Клиент {peer}")
            try:
                data = await reader.read(4096)
                if not data:
                    return

                req_text = data.decode('utf-8', errors='replace').strip()

                if req_text.upper().startswith('CONNECT'):
                    # === HTTPS туннель ===
                    try:
                        target_line = req_text.split('\r\n')[0]
                        target = target_line.split(' ')[1]  # host:port
                        host, port = target.split(':')
                        port = int(port)

                    except Exception:
                        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        await writer.drain()
                        return

                    # Сохраняем идентификатор туннеля для лога
                    tunnel_id = f"{peer} <-> {host}:{port}"
                    log(f"PROXY | 🔒 CONNECT -> {host}:{port}")
                    
                    try:
                        tr, tw = await asyncio.open_connection(host, port)
                    except OSError as e:
                        log(f"PROXY | ! Не удалось подключиться к {host}:{port}: {e}")
                        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        await writer.drain()
                        writer.close()
                        return

                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()
                    log(f"PROXY | ✅ Туннель {tunnel_id}")

                    await asyncio.gather(
                        forward_bytes(reader, tw, f"{peer}->target"),
                        forward_bytes(tr, writer, f"target->{peer}")
                    )
                    log(f"PROXY | 🔌 Туннель {tunnel_id} закрыт")

                else:
                    # === Обычный HTTP ===
                    log(f"PROXY | <<< HTTP ЗАПРОС >>>\n{req_text}")
                    try:
                        target_host, target_port = self._parse_http_target(req_text)
                        log(f"PROXY | 🎯 HTTP -> {target_host}:{target_port}")
                        
                        tr, tw = await asyncio.open_connection(target_host, target_port)
                        tw.write(data)
                        await tw.drain()
                        
                        # Читаем ответ (в продакшене тут цикл по Content-Length/Chunked)
                        resp = await tr.read(65536)
                        log(f"PROXY | >>> HTTP ОТВЕТ <<<\n{resp.decode(errors='replace')[:200]}...")
                        writer.write(resp)
                        await writer.drain()
                        
                    except ValueError as e:
                        log(f"PROXY | ! Ошибка парсинга HTTP: {e}")
                        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        await writer.drain()
                    except ConnectionRefusedError:
                        log(f"PROXY | ! Цель не отвечает")
                        writer.write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                        await writer.drain()
                    except Exception as e:
                        log(f"PROXY | ! HTTP error: {e}")

            except (ConnectionResetError, BrokenPipeError):
                pass
            except Exception as e:
                log(f"PROXY | ! Handler error: {e}")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass

        # === Запуск сервера ===
        self.server = await asyncio.start_server(handle_client, '127.0.0.1', self.listen_port)
        log(f"PROXY | 🕵️ Запущен на 127.0.0.1:{self.listen_port}")
        
        async with self.server:
            await self.server.serve_forever()

    def _parse_http_target(self, req_text):
        """Извлекает хост и порт из HTTP-запроса"""
        first_line = req_text.split('\r\n')[0]
        parts = first_line.split(' ')
        if len(parts) < 3:
            raise ValueError("Invalid request line")
        
        uri = parts[1]
        host = None
        port = 80
        
        # Браузеры через прокси обычно шлют абсолютный URI: GET http://site.com/path
        if uri.startswith('http://'):
            parsed = urlparse(uri)
            host = parsed.hostname
            port = parsed.port or 80
        else:
            # Или относительный: GET /path, тогда хост берём из заголовка Host:
            for line in req_text.split('\r\n'):
                if line.lower().startswith('host:'):
                    host_val = line.split(':', 1)[1].strip()
                    if ':' in host_val:
                        host, port_str = host_val.split(':', 1)
                        port = int(port_str)
                    else:
                        host = host_val
                    break
        
        if not host:
            raise ValueError("Host не найден в запросе")
        return host, port

    async def _cleanup(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            log("PROXY | 🧹 Ресурсы очищены")

    def stop(self):
        if self.loop and self.loop.is_running() and self.server:
            log("PROXY | ⏹ Остановка...")
            asyncio.run_coroutine_threadsafe(self._do_stop(), self.loop)

    async def _do_stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)

# ================= GUI =================
class ProxyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 Forward Proxy Lab")
        self.root.geometry("800x550")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.proxy_port = tk.IntVar(value=8000)
        self.proxy_thread = None
        self.proxy_worker = None

        self.build_ui()
        self.poll_logs()

    def build_ui(self):
        ctrl = ttk.Frame(self.root, padding=10)
        ctrl.pack(fill=tk.X)

        ttk.Label(ctrl, text="Proxy порт:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.proxy_port, width=6).pack(side=tk.LEFT, padx=5)
        self.btn_proxy = ttk.Button(ctrl, text="▶ Запустить Proxy", command=self.toggle_proxy)
        self.btn_proxy.pack(side=tk.LEFT, padx=5)

        ttk.Button(ctrl, text="🗑 Очистить лог", command=self.clear_log).pack(side=tk.RIGHT)

        log_frame = ttk.Frame(self.root, padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED, wrap=tk.WORD, font=("Consolas", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar(value="⏸ Готов к работе")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_proxy(self):
        if self.proxy_thread and self.proxy_thread.is_alive():
            self.proxy_worker.stop()
            self.btn_proxy.config(text="▶ Запустить Proxy")
            self.status_var.set("⏸ Proxy остановлен")
        else:
            listen = self.proxy_port.get()
            self.proxy_worker = ProxyWorker(listen)
            self.proxy_thread = threading.Thread(target=self.proxy_worker.start, daemon=True)
            self.proxy_thread.start()
            self.btn_proxy.config(text="⏹ Остановить Proxy")
            self.status_var.set("🕵️ Proxy работает")

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def poll_logs(self):
        try:
            while not LOG_QUEUE.empty():
                msg = LOG_QUEUE.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                if "ЗАПРОС" in msg: color = "blue"
                elif "ОТВЕТ" in msg or "✅" in msg: color = "green"
                elif "Ошибка" in msg or "❌" in msg or "🔒" in msg: color = "red"
                elif "Туннель" in msg or "🎯" in msg: color = "purple"
                else: color = "black"
                self.log_text.insert(tk.END, msg + "\n", color)
                self.log_text.tag_config(color, foreground=color)
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_logs)

    def on_close(self):
        if self.proxy_thread and self.proxy_thread.is_alive():
            self.proxy_worker.stop()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ProxyGUI(root)
    root.mainloop()