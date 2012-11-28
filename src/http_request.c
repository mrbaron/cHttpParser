

/*
 *  used for http header
 *
 * */
int parse_request_line(http_request_t *request, u_char *buf, size_t len) {
    state_t state = sw_start;
    u_char *p = buf;
    u_char *last = buf + len;
    u_char ch;
    u_char *m;

    for(; p < last; p++) {
        ch = *p;

        switch (state) {

            /* HTTP methods: GET, HEAD, POST */
            case sw_start:
                r->request_start = p;

                if (ch == CR || ch == LF) {
                    break;
                }

                if ((ch < 'A' || ch > 'Z') && ch != '_') {
                    return HTTP_PARSE_INVALID_METHOD;
                }

                state = sw_method;
                break;

            case sw_method:
                if (ch == ' ') {
                    r->method_end = p - 1;
                    m = r->request_start;

                    switch (p - m) {

                        case 3:
                            if (str3_cmp(m, 'G', 'E', 'T', ' ')) {
                                r->method = HTTP_GET;
                                break;
                            }

                            if (str3_cmp(m, 'P', 'U', 'T', ' ')) {
                                r->method = HTTP_PUT;
                                break;
                            }

                            break;

                        case 4:
                            if (m[1] == 'O') {

                                if (str3Ocmp(m, 'P', 'O', 'S', 'T')) {
                                    r->method = HTTP_POST;
                                    break;
                                }

                                if (str3Ocmp(m, 'C', 'O', 'P', 'Y')) {
                                    r->method = HTTP_COPY;
                                    break;
                                }

                                if (str3Ocmp(m, 'M', 'O', 'V', 'E')) {
                                    r->method = HTTP_MOVE;
                                    break;
                                }

                                if (str3Ocmp(m, 'L', 'O', 'C', 'K')) {
                                    r->method = HTTP_LOCK;
                                    break;
                                }

                            } else {

                                if (str4cmp(m, 'H', 'E', 'A', 'D')) {
                                    r->method = HTTP_HEAD;
                                    break;
                                }
                            }

                            break;

                        case 5:
                            if (str5cmp(m, 'M', 'K', 'C', 'O', 'L')) {
                                r->method = HTTP_MKCOL;
                            }

                            if (str5cmp(m, 'P', 'A', 'T', 'C', 'H')) {
                                r->method = HTTP_PATCH;
                            }

                            if (str5cmp(m, 'T', 'R', 'A', 'C', 'E')) {
                                r->method = HTTP_TRACE;
                            }

                            break;

                        case 6:
                            if (str6cmp(m, 'D', 'E', 'L', 'E', 'T', 'E')) {
                                r->method = HTTP_DELETE;
                                break;
                            }

                            if (str6cmp(m, 'U', 'N', 'L', 'O', 'C', 'K')) {
                                r->method = HTTP_UNLOCK;
                                break;
                            }

                            break;

                        case 7:
                            if (str7_cmp(m, 'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '))
                            {
                                r->method = HTTP_OPTIONS;
                            }

                            break;

                        case 8:
                            if (str8cmp(m, 'P', 'R', 'O', 'P', 'F', 'I', 'N', 'D'))
                            {
                                r->method = HTTP_PROPFIND;
                            }

                            break;

                        case 9:
                            if (str9cmp(m,
                                        'P', 'R', 'O', 'P', 'P', 'A', 'T', 'C', 'H'))
                            {
                                r->method = HTTP_PROPPATCH;
                            }

                            break;
                    }

                    state = sw_spaces_before_uri;
                    break;
                }

                if ((ch < 'A' || ch > 'Z') && ch != '_') {
                    return HTTP_PARSE_INVALID_METHOD;
                }

                break;

                /* space* before URI */
            case sw_spaces_before_uri:

                if (ch == '/') {
                    r->uri_start = p;
                    state = sw_after_slash_in_uri;
                    break;
                }

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    r->schema_start = p;
                    state = sw_schema;
                    break;
                }

                switch (ch) {
                    case ' ':
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

            case sw_schema:

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                switch (ch) {
                    case ':':
                        r->schema_end = p;
                        state = sw_schema_slash;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

            case sw_schema_slash:
                switch (ch) {
                    case '/':
                        state = sw_schema_slash_slash;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

            case sw_schema_slash_slash:
                switch (ch) {
                    case '/':
                        state = sw_host_start;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

            case sw_host_start:

                r->host_start = p;

                if (ch == '[') {
                    state = sw_host_ip_literal;
                    break;
                }

                state = sw_host;

                /* fall through */

            case sw_host:

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                    break;
                }

                /* fall through */

            case sw_host_end:

                r->host_end = p;

                switch (ch) {
                    case ':':
                        state = sw_port;
                        break;
                    case '/':
                        r->uri_start = p;
                        state = sw_after_slash_in_uri;
                        break;
                    case ' ':
                        /*
                         * use single "/" from request line to preserve pointers,
                         * if request line will be copied to large client buffer
                         */
                        r->uri_start = r->schema_end + 1;
                        r->uri_end = r->schema_end + 2;
                        state = sw_host_http_09;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

            case sw_host_ip_literal:

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                switch (ch) {
                    case ':':
                        break;
                    case ']':
                        state = sw_host_end;
                        break;
                    case '-':
                    case '.':
                    case '_':
                    case '~':
                        /* unreserved */
                        break;
                    case '!':
                    case '$':
                    case '&':
                    case '\'':
                    case '(':
                    case ')':
                    case '*':
                    case '+':
                    case ',':
                    case ';':
                    case '=':
                        /* sub-delims */
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

            case sw_port:
                if (ch >= '0' && ch <= '9') {
                    break;
                }

                switch (ch) {
                    case '/':
                        r->port_end = p;
                        r->uri_start = p;
                        state = sw_after_slash_in_uri;
                        break;
                    case ' ':
                        r->port_end = p;
                        /*
                         * use single "/" from request line to preserve pointers,
                         * if request line will be copied to large client buffer
                         */
                        r->uri_start = r->schema_end + 1;
                        r->uri_end = r->schema_end + 2;
                        state = sw_host_http_09;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

                /* space+ after "http://host[:port] " */
            case sw_host_http_09:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        r->http_minor = 9;
                        state = sw_almost_done;
                        break;
                    case LF:
                        r->http_minor = 9;
                        goto done;
                    case 'H':
                        r->http_protocol.data = p;
                        state = sw_http_H;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;


                /* check "/.", "//", "%", and "\" (Win32) in URI */
            case sw_after_slash_in_uri:

                if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                    state = sw_check_uri;
                    break;
                }

                switch (ch) {
                    case ' ':
                        r->uri_end = p;
                        state = sw_check_uri_http_09;
                        break;
                    case CR:
                        r->uri_end = p;
                        r->http_minor = 9;
                        state = sw_almost_done;
                        break;
                    case LF:
                        r->uri_end = p;
                        r->http_minor = 9;
                        goto done;
                    case '.':
                        r->complex_uri = 1;
                        state = sw_uri;
                        break;
                    case '%':
                        r->quoted_uri = 1;
                        state = sw_uri;
                        break;
                    case '/':
                        r->complex_uri = 1;
                        state = sw_uri;
                        break;
#if (WIN32)
                    case '\\':
                        r->complex_uri = 1;
                        state = sw_uri;
                        break;
#endif
                    case '?':
                        r->args_start = p + 1;
                        state = sw_uri;
                        break;
                    case '#':
                        r->complex_uri = 1;
                        state = sw_uri;
                        break;
                    case '+':
                        r->plus_in_uri = 1;
                        break;
                    case '\0':
                        return HTTP_PARSE_INVALID_REQUEST;
                    default:
                        state = sw_check_uri;
                        break;
                }
                break;

                /* check "/", "%" and "\" (Win32) in URI */
            case sw_check_uri:

                if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                    break;
                }

                switch (ch) {
                    case '/':
                        r->uri_ext = NULL;
                        state = sw_after_slash_in_uri;
                        break;
                    case '.':
                        r->uri_ext = p + 1;
                        break;
                    case ' ':
                        r->uri_end = p;
                        state = sw_check_uri_http_09;
                        break;
                    case CR:
                        r->uri_end = p;
                        r->http_minor = 9;
                        state = sw_almost_done;
                        break;
                    case LF:
                        r->uri_end = p;
                        r->http_minor = 9;
                        goto done;
#if (WIN32)
                    case '\\':
                        r->complex_uri = 1;
                        state = sw_after_slash_in_uri;
                        break;
#endif
                    case '%':
                        r->quoted_uri = 1;
                        state = sw_uri;
                        break;
                    case '?':
                        r->args_start = p + 1;
                        state = sw_uri;
                        break;
                    case '#':
                        r->complex_uri = 1;
                        state = sw_uri;
                        break;
                    case '+':
                        r->plus_in_uri = 1;
                        break;
                    case '\0':
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

                /* space+ after URI */
            case sw_check_uri_http_09:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        r->http_minor = 9;
                        state = sw_almost_done;
                        break;
                    case LF:
                        r->http_minor = 9;
                        goto done;
                    case 'H':
                        r->http_protocol.data = p;
                        state = sw_http_H;
                        break;
                    default:
                        r->space_in_uri = 1;
                        state = sw_check_uri;
                        break;
                }
                break;


                /* URI */
            case sw_uri:

                if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                    break;
                }

                switch (ch) {
                    case ' ':
                        r->uri_end = p;
                        state = sw_http_09;
                        break;
                    case CR:
                        r->uri_end = p;
                        r->http_minor = 9;
                        state = sw_almost_done;
                        break;
                    case LF:
                        r->uri_end = p;
                        r->http_minor = 9;
                        goto done;
                    case '#':
                        r->complex_uri = 1;
                        break;
                    case '\0':
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

                /* space+ after URI */
            case sw_http_09:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        r->http_minor = 9;
                        state = sw_almost_done;
                        break;
                    case LF:
                        r->http_minor = 9;
                        goto done;
                    case 'H':
                        r->http_protocol.data = p;
                        state = sw_http_H;
                        break;
                    default:
                        r->space_in_uri = 1;
                        state = sw_uri;
                        break;
                }
                break;

            case sw_http_H:
                switch (ch) {
                    case 'T':
                        state = sw_http_HT;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

            case sw_http_HT:
                switch (ch) {
                    case 'T':
                        state = sw_http_HTT;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

            case sw_http_HTT:
                switch (ch) {
                    case 'P':
                        state = sw_http_HTTP;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

            case sw_http_HTTP:
                switch (ch) {
                    case '/':
                        state = sw_first_major_digit;
                        break;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

                /* first digit of major HTTP version */
            case sw_first_major_digit:
                if (ch < '1' || ch > '9') {
                    return HTTP_PARSE_INVALID_REQUEST;
                }

                r->http_major = ch - '0';
                state = sw_major_digit;
                break;

                /* major HTTP version or dot */
            case sw_major_digit:
                if (ch == '.') {
                    state = sw_first_minor_digit;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return HTTP_PARSE_INVALID_REQUEST;
                }

                r->http_major = r->http_major * 10 + ch - '0';
                break;

                /* first digit of minor HTTP version */
            case sw_first_minor_digit:
                if (ch < '0' || ch > '9') {
                    return HTTP_PARSE_INVALID_REQUEST;
                }

                r->http_minor = ch - '0';
                state = sw_minor_digit;
                break;

                /* minor HTTP version or end of request line */
            case sw_minor_digit:
                if (ch == CR) {
                    state = sw_almost_done;
                    break;
                }

                if (ch == LF) {
                    goto done;
                }

                if (ch == ' ') {
                    state = sw_spaces_after_digit;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return HTTP_PARSE_INVALID_REQUEST;
                }

                r->http_minor = r->http_minor * 10 + ch - '0';
                break;

           case fter_digit:
                switch (ch) {
                   case ' ':
                        break;
                    case CR:
                        state = sw_almost_done;
                        break;
                    case LF:
                        goto done;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
                break;

                /* end of request line */
            case sw_almost_done:
                r->request_end = p - 1;
                switch (ch) {
                    case LF:
                        goto done;
                    default:
                        return HTTP_PARSE_INVALID_REQUEST;
                }
        }
    }

    return 0;
}
