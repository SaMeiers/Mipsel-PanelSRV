#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LISTEN_PORT   8080
#define TOKEN         "change"
#define TOOLS_DIR     "/tmp/tools"
#define JOBS_DIR      "/tmp/jobs"
#define MAX_REQUEST   (4*1024*1024)
#define BACKLOG       8

static const char *PANEL_HTML =
"<!DOCTYPE html><html><head><meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Extensor Panel</title><style>"
"body{background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0;padding:16px}"
"h2{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:6px}"
"input,select,button{background:#161b22;color:#c9d1d9;border:1px solid #30363d;"
"padding:8px;border-radius:6px;font-family:monospace;width:100%;box-sizing:border-box;margin:4px 0}"
"button{cursor:pointer;background:#238636;border:none}"
"button:active{background:#2ea043}"
"pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px;"
"min-height:140px;max-height:320px;overflow:auto;white-space:pre-wrap;word-break:break-all}"
"section{margin-bottom:24px}.row{display:flex;gap:8px}.row>*{flex:1}"
"</style></head><body>"
"<h2>Consola</h2><section>"
"<input id='cmd' placeholder='comando...' onkeydown='if(event.key==\"Enter\")runCmd()'>"
"<button onclick='runCmd()'>Ejecutar</button>"
"<pre id='out'>(sin output)</pre></section>"
"<h2>WiFi / Ataques</h2><section>"
"<button onclick=\"runRaw('/tmp/scripts/attack.sh scan')\">Escanear redes</button>"
"<input id='bssid' placeholder='BSSID objetivo (copialo del scan de arriba)'>"
"<input id='chan' placeholder='Canal (ej: 6)'>"
"<div class='row'>"
"<button onclick=\"attack('wps')\">Atacar WPS</button>"
"<button onclick=\"attack('capture')\">Capturar handshake</button>"
"</div></section>"
"<h2>Subir binario</h2><section>"
"<input type='file' id='file'>"
"<button onclick='upload()'>Subir a /tmp/tools</button>"
"<pre id='upout'>(nada subido)</pre></section>"
"<script>"
"const TOKEN='" TOKEN "';let poll=null;"
"function showOut(id){clearInterval(poll);"
"poll=setInterval(()=>{fetch('/output?token='+TOKEN+'&id='+id).then(r=>r.text()).then(t=>{"
"document.getElementById('out').textContent=t;"
"if(t.indexOf('___JOB_DONE___')>=0)clearInterval(poll);});},1500);}"
"function runRaw(cmd){fetch('/run?token='+TOKEN,{method:'POST',"
"headers:{'Content-Type':'application/x-www-form-urlencoded'},"
"body:'cmd='+encodeURIComponent(cmd)}).then(r=>r.text()).then(id=>showOut(id.trim()));}"
"function runCmd(){runRaw(document.getElementById('cmd').value);}"
"function attack(mode){const b=document.getElementById('bssid').value;"
"const c=document.getElementById('chan').value;"
"if(!b){alert('Pon el BSSID objetivo primero');return;}"
"runRaw('/tmp/scripts/attack.sh '+mode+' '+b+' '+c);}"
"function upload(){const f=document.getElementById('file').files[0];"
"if(!f){alert('Elige un archivo');return;}"
"const fd=new FormData();fd.append('file',f,f.name);"
"fetch('/upload?token='+TOKEN,{method:'POST',body:fd}).then(r=>r.text()).then(t=>{"
"document.getElementById('upout').textContent=t;});}"
"</script></body></html>";

static void send_response(int fd, const char *status, const char *ctype,
                           const char *body, size_t blen) {
    char head[256];
    int hl = snprintf(head, sizeof(head),
        "HTTP/1.0 %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
        status, ctype, (unsigned long)blen);
    if (hl > 0) {
        ssize_t off = 0;
        while (off < hl) {
            ssize_t w = write(fd, head + off, hl - off);
            if (w <= 0) return;
            off += w;
        }
    }
    size_t off = 0;
    while (off < blen) {
        ssize_t w = write(fd, body + off, blen - off);
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static void send_text(int fd, const char *status, const char *text) {
    send_response(fd, status, "text/plain", text, strlen(text));
}

static char *find_bytes(char *hay, size_t hlen, const char *needle, size_t nlen) {
    if (nlen == 0 || hlen < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
    }
    return NULL;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(char *s) {
    char *w = s;
    while (*s) {
        if (*s == '+') { *w++ = ' '; s++; }
        else if (*s == '%' && s[1] && s[2]) {
            int hi = hexval(s[1]), lo = hexval(s[2]);
            if (hi >= 0 && lo >= 0) { *w++ = (char)((hi << 4) | lo); s += 3; }
            else { *w++ = *s++; }
        } else { *w++ = *s++; }
    }
    *w = '\0';
}

static int get_param(const char *qs, const char *name, char *out, size_t outsz) {
    if (!qs) return 0;
    size_t nlen = strlen(name);
    const char *p = qs;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seglen = amp ? (size_t)(amp - p) : strlen(p);
        if (seglen > nlen && p[nlen] == '=' && strncmp(p, name, nlen) == 0) {
            size_t vlen = seglen - nlen - 1;
            if (vlen >= outsz) vlen = outsz - 1;
            memcpy(out, p + nlen + 1, vlen);
            out[vlen] = '\0';
            url_decode(out);
            return 1;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static int check_token(const char *query) {
    char tok[128];
    if (!get_param(query, "token", tok, sizeof(tok))) return 0;
    return strcmp(tok, TOKEN) == 0;
}

static int valid_id_char(char c) {
    return isalnum((unsigned char)c) || c == '_' || c == '-';
}

static void handle_run(int fd, const char *query, char *body, size_t blen) {
    if (!check_token(query)) { send_text(fd, "403 Forbidden", "token invalido"); return; }

    char cmd[2048];
    char tmp[2048];
    if (blen >= sizeof(tmp)) blen = sizeof(tmp) - 1;
    memcpy(tmp, body, blen);
    tmp[blen] = '\0';
    if (!get_param(tmp, "cmd", cmd, sizeof(cmd)) || cmd[0] == '\0') {
        send_text(fd, "400 Bad Request", "falta cmd");
        return;
    }

    mkdir(JOBS_DIR, 0755);
    static int counter = 0;
    char jobid[64];
    snprintf(jobid, sizeof(jobid), "%ld_%d", (long)time(NULL), counter++);

    char logpath[256];
    snprintf(logpath, sizeof(logpath), "%s/%s.log", JOBS_DIR, jobid);

    char fullcmd[2200];
    snprintf(fullcmd, sizeof(fullcmd), "(%s); echo ___JOB_DONE___", cmd);

    pid_t p1 = fork();
    if (p1 == 0) {
        setsid();
        pid_t p2 = fork();
        if (p2 == 0) {
            int lfd = open(logpath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (lfd >= 0) { dup2(lfd, 1); dup2(lfd, 2); close(lfd); }
            execl("/bin/sh", "sh", "-c", fullcmd, (char *)NULL);
            _exit(127);
        }
        _exit(0);
    }
    waitpid(p1, NULL, 0);

    send_text(fd, "200 OK", jobid);
}

static void handle_output(int fd, const char *query) {
    if (!check_token(query)) { send_text(fd, "403 Forbidden", "token invalido"); return; }

    char id[64];
    if (!get_param(query, "id", id, sizeof(id))) {
        send_text(fd, "400 Bad Request", "falta id");
        return;
    }
    for (char *c = id; *c; c++) {
        if (!valid_id_char(*c)) { send_text(fd, "400 Bad Request", "id invalido"); return; }
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/%s.log", JOBS_DIR, id);
    FILE *f = fopen(path, "rb");
    if (!f) { send_text(fd, "200 OK", "(aun sin output...)"); return; }

    char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    send_text(fd, "200 OK", buf);
}

static void handle_upload(int fd, const char *query, const char *content_type,
                           char *body, size_t blen) {
    if (!check_token(query)) { send_text(fd, "403 Forbidden", "token invalido"); return; }

    const char *bmark = content_type ? strstr(content_type, "boundary=") : NULL;
    if (!bmark) { send_text(fd, "400 Bad Request", "sin boundary"); return; }
    bmark += strlen("boundary=");

    char boundary[256];
    snprintf(boundary, sizeof(boundary), "--%s", bmark);
    size_t blen2 = strlen(boundary);
    while (blen2 > 0 && (boundary[blen2 - 1] == '\r' || boundary[blen2 - 1] == '\n' ||
                          boundary[blen2 - 1] == ' ')) {
        boundary[--blen2] = '\0';
    }

    char *part = find_bytes(body, blen, boundary, blen2);
    if (!part) { send_text(fd, "400 Bad Request", "boundary no encontrado"); return; }
    part += blen2;

    char *hdr_end = find_bytes(part, (size_t)(body + blen - part), "\r\n\r\n", 4);
    if (!hdr_end) { send_text(fd, "400 Bad Request", "headers de parte invalidos"); return; }

    char part_headers[1024];
    size_t hlen = (size_t)(hdr_end - part);
    if (hlen >= sizeof(part_headers)) hlen = sizeof(part_headers) - 1;
    memcpy(part_headers, part, hlen);
    part_headers[hlen] = '\0';

    char filename[256] = "subida.bin";
    char *fn = strstr(part_headers, "filename=\"");
    if (fn) {
        fn += strlen("filename=\"");
        char *fnend = strchr(fn, '"');
        if (fnend) {
            size_t flen = (size_t)(fnend - fn);
            if (flen >= sizeof(filename)) flen = sizeof(filename) - 1;
            memcpy(filename, fn, flen);
            filename[flen] = '\0';
        }
    }
    char *base = strrchr(filename, '/');
    base = base ? base + 1 : filename;
    for (char *c = base; *c; c++) {
        if (!isalnum((unsigned char)*c) && *c != '.' && *c != '_' && *c != '-') *c = '_';
    }

    char *data_start = hdr_end + 4;
    char *body_end = body + blen;
    char *next_boundary = find_bytes(data_start, (size_t)(body_end - data_start),
                                      boundary, blen2);
    if (!next_boundary) { send_text(fd, "400 Bad Request", "fin de parte no encontrado"); return; }

    size_t data_len = (size_t)(next_boundary - data_start);
    if (data_len >= 2 && data_start[data_len - 2] == '\r' && data_start[data_len - 1] == '\n') {
        data_len -= 2;
    }

    mkdir(TOOLS_DIR, 0755);
    char outpath[300];
    snprintf(outpath, sizeof(outpath), "%s/%s", TOOLS_DIR, base);
    FILE *out = fopen(outpath, "wb");
    if (!out) { send_text(fd, "500 Internal Server Error", "no se pudo escribir"); return; }
    fwrite(data_start, 1, data_len, out);
    fclose(out);
    chmod(outpath, 0755);

    char msg[400];
    snprintf(msg, sizeof(msg), "OK: %s (%lu bytes) -> %s",
             base, (unsigned long)data_len, outpath);
    send_text(fd, "200 OK", msg);
}

static char *find_header_value(const char *headers, const char *name, char *out, size_t outsz) {
    char search[64];
    snprintf(search, sizeof(search), "\n%s:", name);
    size_t slen = strlen(search);
    size_t hlen = strlen(headers);
    const char *p = NULL;
    for (size_t i = 0; i + slen <= hlen; i++) {
        if (strncasecmp(headers + i, search, slen) == 0) { p = headers + i; break; }
    }
    if (!p) return NULL;
    p += strlen(search);
    while (*p == ' ') p++;
    const char *end = strpbrk(p, "\r\n");
    size_t vlen = end ? (size_t)(end - p) : strlen(p);
    if (vlen >= outsz) vlen = outsz - 1;
    memcpy(out, p, vlen);
    out[vlen] = '\0';
    return out;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    mkdir(TOOLS_DIR, 0755);
    mkdir(JOBS_DIR, 0755);
    mkdir("/tmp/scripts", 0755);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(srv, BACKLOG) < 0) { perror("listen"); return 1; }

    fprintf(stderr, "panelsrv escuchando en :%d\n", LISTEN_PORT);

    static char reqbuf[MAX_REQUEST];

    for (;;) {
        int cfd = accept(srv, NULL, NULL);
        if (cfd < 0) continue;

        size_t total = 0;
        ssize_t n;
        char *header_end = NULL;
        while (total < sizeof(reqbuf) - 1) {
            n = read(cfd, reqbuf + total, sizeof(reqbuf) - 1 - total);
            if (n <= 0) break;
            total += (size_t)n;
            reqbuf[total] = '\0';
            header_end = strstr(reqbuf, "\r\n\r\n");
            if (header_end) break;
        }

        if (!header_end) { close(cfd); continue; }

        size_t header_len = (size_t)(header_end - reqbuf) + 4;
        char headers[8192];
        size_t hcopy = header_len < sizeof(headers) ? header_len : sizeof(headers) - 1;
        memcpy(headers, reqbuf, hcopy);
        headers[hcopy] = '\0';

        char clen_s[32] = "0";
        find_header_value(headers, "Content-Length", clen_s, sizeof(clen_s));
        long content_length = atol(clen_s);
        if (content_length < 0) content_length = 0;
        if ((size_t)content_length > sizeof(reqbuf) - header_len - 1)
            content_length = (long)(sizeof(reqbuf) - header_len - 1);

        size_t body_have = total - header_len;
        while (body_have < (size_t)content_length) {
            n = read(cfd, reqbuf + total, sizeof(reqbuf) - 1 - total);
            if (n <= 0) break;
            total += (size_t)n;
            body_have += (size_t)n;
        }
        char *body = reqbuf + header_len;

        char method[8] = "", path[512] = "", query[1024] = "";
        sscanf(reqbuf, "%7s %511s", method, path);
        char *qmark = strchr(path, '?');
        if (qmark) { strncpy(query, qmark + 1, sizeof(query) - 1); *qmark = '\0'; }

        char ctype[256] = "";
        find_header_value(headers, "Content-Type", ctype, sizeof(ctype));

        if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
            send_response(cfd, "200 OK", "text/html", PANEL_HTML, strlen(PANEL_HTML));
        } else if (strcmp(method, "GET") == 0 && strcmp(path, "/output") == 0) {
            handle_output(cfd, query);
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/run") == 0) {
            handle_run(cfd, query, body, body_have);
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/upload") == 0) {
            handle_upload(cfd, query, ctype, body, body_have);
        } else {
            send_text(cfd, "404 Not Found", "ruta desconocida");
        }

        close(cfd);
    }
    return 0;
}
