# Функция проверки сайта для web-atelie.ru/proverka-saita/ (Yandex Cloud Functions, Python 3.12).
# Вызов: GET https://functions.yandexcloud.net/<id>?url=mysite.ru
# Ответ: {"url": ..., "final": ..., "checks": {<id>: {"s": "ok"|"warn"|"bad"|"skip", "t": "пояснение"}}}
# Только стандартная библиотека Python. Читает только главную страницу, формы не отправляет.
import json, re, socket, ssl, time, ipaddress, html
from urllib.parse import urlsplit, urljoin
import http.client

UA = 'Mozilla/5.0 (compatible; WebAtelieCheck/1.0; +https://web-atelie.ru/proverka-saita/)'
MAX_BYTES = 3_000_000
TIMEOUT = 10
CORS = {'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type', 'Content-Type': 'application/json; charset=utf-8'}


class CheckError(Exception):
    pass


def norm(u):
    u = (u or '').strip()
    if not u:
        raise CheckError('Не указан адрес сайта')
    if not re.match(r'^https?://', u, re.I):
        u = 'https://' + u
    p = urlsplit(u)
    if p.scheme not in ('http', 'https') or not p.hostname or '.' not in p.hostname:
        raise CheckError('Похоже, это не адрес сайта')
    return u


def safe_host(host):
    # не даём проверять внутренние адреса (защита облака от обращений «внутрь»)
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise CheckError('Такого сайта не существует или он не отвечает')
    for i in infos:
        ip = ipaddress.ip_address(i[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise CheckError('Этот адрес нельзя проверить')


def get(url):
    """Один запрос без автоматических переходов. Возвращает (код, заголовки, тело, ошибка_сертификата)."""
    p = urlsplit(url)
    safe_host(p.hostname)
    path = (p.path or '/') + ('?' + p.query if p.query else '')
    if p.scheme == 'https':
        conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=TIMEOUT, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=TIMEOUT)
    conn.request('GET', path, headers={'User-Agent': UA, 'Accept': 'text/html,*/*', 'Accept-Language': 'ru'})
    r = conn.getresponse()
    body = r.read(MAX_BYTES) if r.status < 300 else b''
    hdr = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return r.status, hdr, body


def follow(url, limit=8):
    """Идём по переходам вручную, чтобы посчитать цепочку."""
    chain = [url]
    for _ in range(limit):
        st, hdr, body = get(url)
        if st in (301, 302, 303, 307, 308) and hdr.get('location'):
            url = urljoin(url, hdr['location'])
            chain.append(url)
            continue
        return st, hdr, body, chain
    raise CheckError('Сайт бесконечно перенаправляет сам на себя')


def decode(body, hdr):
    m = re.search(r'charset=([\w-]+)', hdr.get('content-type', ''), re.I) or \
        re.search(rb'<meta[^>]+charset=["\']?([\w-]+)', body[:4000], re.I)
    cs = m.group(1) if m else 'utf-8'
    if isinstance(cs, bytes):
        cs = cs.decode('ascii', 'ignore')
    try:
        return body.decode(cs, 'replace')
    except LookupError:
        return body.decode('utf-8', 'replace')


def text_of(h):
    h = re.sub(r'(?is)<(script|style|noscript|svg)[^>]*>.*?</\1>', ' ', h)
    return re.sub(r'\s+', ' ', html.unescape(re.sub(r'(?s)<[^>]+>', ' ', h)))


def meta(h, attr, name):
    for tag in re.findall(r'(?is)<meta\b[^>]*>', h):
        if re.search(r'%s\s*=\s*["\']%s["\']' % (attr, re.escape(name)), tag, re.I):
            m = re.search(r'content\s*=\s*["\']([^"\']*)', tag, re.I)
            if m:
                return html.unescape(m.group(1)).strip()
    return None


def plural(n, a, b, c):
    n = abs(n) % 100
    return a if n % 10 == 1 and n != 11 else b if 2 <= n % 10 <= 4 and not 12 <= n <= 14 else c


def run(url):
    c = {}
    t0 = time.time()
    try:
        st, hdr, body, chain = follow(url)
    except ssl.SSLError:
        c['open'] = {'s': 'bad', 't': 'Браузер покажет предупреждение: сертификат безопасности недействителен'}
        c['https'] = {'s': 'bad', 't': 'Сертификат HTTPS недействителен или просрочен'}
        return c, url
    except (socket.timeout, TimeoutError):
        raise CheckError('Сайт не ответил за 10 секунд')
    except (ConnectionError, OSError) as e:
        raise CheckError('Не удалось открыть сайт')
    dt = time.time() - t0
    final = chain[-1]

    # --- Сайт открывается
    if st >= 400:
        c['open'] = {'s': 'bad', 't': f'Сервер ответил ошибкой {st}'}
        return c, final
    sec = f'{dt:.1f}'.replace('.', ',')
    c['open'] = {'s': 'ok' if dt < 3 else 'warn', 't': f'Страница пришла за {sec} с' + ('' if dt < 3 else ' – это долго')}

    # --- HTTPS
    if not final.startswith('https://'):
        c['https'] = {'s': 'bad', 't': 'Сайт открывается без HTTPS – браузер пишет «Не защищено»'}
    else:
        http_ok = None
        try:
            hu = 'http://' + final[len('https://'):]
            _, _, _, hchain = follow(hu, 5)
            http_ok = hchain[-1].startswith('https://')
        except Exception:
            pass
        if http_ok is False:
            c['https'] = {'s': 'warn', 't': 'HTTPS есть, но адрес с http:// не переводит на защищённую версию'}
        else:
            c['https'] = {'s': 'ok', 't': 'HTTPS есть, сертификат действует'}

    # --- Переходы
    hops = len(chain) - 1
    if hops <= 1:
        c['redir'] = {'s': 'ok', 't': 'Без лишних переходов' if hops == 0 else 'Один переход – это нормально'}
    else:
        c['redir'] = {'s': 'warn' if hops == 2 else 'bad', 't': f'{hops} {plural(hops, "переход", "перехода", "переходов")} подряд перед открытием сайта'}

    h = decode(body, hdr)
    txt = text_of(h)
    low = h.lower()
    tl = txt.lower()
    kb = len(body) // 1024

    # --- Скорость, вес, картинки, кнопки – отдельным запросом ?part=speed (Google PageSpeed, 20–40 с)

    # --- Телефон
    if re.search(r'name=["\']viewport["\']', low):
        c['mobile'] = {'s': 'ok', 't': 'Сайт настроен под экран телефона'}
    else:
        c['mobile'] = {'s': 'bad', 't': 'Нет настройки под телефон – страница будет мелкой и неудобной'}

    # --- Связь
    tels = set(re.findall(r'href=["\']tel:([^"\']+)', h, re.I))
    phone_text = re.search(r'(\+7|8)[\s\-(]*\d{3}[\s\-)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}', txt)
    if tels:
        c['call'] = {'s': 'ok', 't': 'Телефон набирается в одно нажатие'}
    elif phone_text:
        c['call'] = {'s': 'bad', 't': f'Телефон {phone_text.group(0).strip()} написан текстом – по нажатию не звонит'}
    else:
        c['call'] = {'s': 'bad', 't': 'Телефона на главной не нашли'}

    links = re.findall(r'href=["\']([^"\']+)', h, re.I)
    share = re.compile(r'share|sharer|send\?text|/share/', re.I)
    wa = any(re.search(r'wa\.me/|api\.whatsapp\.com|whatsapp://', l, re.I) and not share.search(l) for l in links)
    tg = any(re.search(r'(t\.me|telegram\.me)/(?!share)', l, re.I) for l in links)
    mx = any(re.search(r'max\.ru/', l, re.I) for l in links)
    got = [n for n, ok in (('WhatsApp', wa), ('Telegram', tg), ('MAX', mx)) if ok]
    if got:
        c['msg'] = {'s': 'ok', 't': 'Есть ' + ', '.join(got)}
    else:
        c['msg'] = {'s': 'warn', 't': 'Кнопок WhatsApp, Telegram или MAX не нашли'}

    forms = len(re.findall(r'<form\b', low))
    widget = re.search(r'yclients|dikidi|bitrix24|b24-|amocrm|t-form|tildacdn.*form|jivo|marquiz|envybox|callibri', low)
    if forms or widget:
        c['form'] = {'s': 'ok', 't': 'Есть форма заявки или онлайн-запись'}
    else:
        c['form'] = {'s': 'warn', 't': 'Формы заявки на главной не нашли'}

    # только целые слова: иначе «вт» находится внутри «автоматически», «ш.» внутри любого слова на «ш»
    addr = re.search(r'(?<![А-Яа-яЁё])(ул\.|улица|пр-т|проспект|пер\.|переулок|шоссе|ш\.|наб\.|набережная|бульвар|б-р|пл\.|площадь)\s*[А-ЯЁA-Z0-9]', txt)
    hours = re.search(r'(?<![а-яё])(пн|пон|ежедневно|без выходных|круглосуточно|часы работы|режим работы|график работы)(?![а-яё])'
                      r'|(?<!\d)\d{1,2}[:.]\d{2}\s*[–—-]\s*\d{1,2}[:.]\d{2}(?!\d)', tl)
    mapw = re.search(r'api-maps\.yandex|yandex\.ru/map-widget|yandex\.ru/maps|2gis|google\.com/maps', low)
    if (addr or mapw) and hours:
        c['addr'] = {'s': 'ok', 't': 'Адрес и часы работы есть'}
    elif addr or mapw or hours:
        c['addr'] = {'s': 'warn', 't': 'Есть адрес, но не нашли часы работы' if (addr or mapw) else 'Есть часы работы, но не нашли адрес'}
    else:
        c['addr'] = {'s': 'warn', 't': 'Адреса и часов работы на главной не нашли'}

    # --- Закон
    policy = re.search(r'политик\w*\s+(обработки|конфиденциальности|в отношении)|персональн\w+ данн', tl) or \
        re.search(r'href=["\'][^"\']*(privacy|policy|politika|konfidenc|personal)', low)
    c['policy'] = {'s': 'ok', 't': 'Ссылка на политику обработки данных есть'} if policy else \
        {'s': 'bad', 't': 'Политику обработки персональных данных не нашли'}
    if forms or widget:
        if re.search(r'соглас\w*[^.]{0,80}(обработк|персональн)|(обработк|персональн)\w*[^.]{0,80}соглас', tl):
            c['consent'] = {'s': 'ok', 't': 'Есть согласие на обработку персональных данных'}
        elif re.search(r'type=["\']checkbox', low):
            c['consent'] = {'s': 'warn', 't': 'Есть галочка у формы, но текст согласия не нашли – проверьте глазами'}
        else:
            c['consent'] = {'s': 'bad', 't': 'Возле формы нет согласия на обработку персональных данных'}
    else:
        c['consent'] = {'s': 'skip', 't': 'Форм нет – проверять нечего'}
    c['cookie'] = {'s': 'ok', 't': 'Предупреждение о cookie есть'} if re.search(r'cookie|куки', tl) else \
        {'s': 'warn', 't': 'Предупреждения о cookie не нашли'}

    # --- Поиск и соцсети
    tm = re.search(r'(?is)<title[^>]*>(.*?)</title>', h)
    title = re.sub(r'\s+', ' ', html.unescape(tm.group(1))).strip() if tm else ''
    desc = meta(h, 'name', 'description') or ''
    if not title:
        c['title'] = {'s': 'bad', 't': 'У страницы нет названия'}
    elif not desc:
        c['title'] = {'s': 'bad', 't': 'Нет описания – поисковик сам выберет кусок текста'}
    elif len(desc) < 50 or len(title) < 10:
        c['title'] = {'s': 'warn', 't': f'Описание слишком короткое: «{desc[:60]}»' if len(desc) < 50 else f'Название слишком короткое: «{title}»'}
    else:
        c['title'] = {'s': 'ok', 't': f'«{title[:60]}»'}
    ogi, ogt = meta(h, 'property', 'og:image'), meta(h, 'property', 'og:title')
    if ogi and ogt:
        c['og'] = {'s': 'ok', 't': 'Картинка и заголовок для превью есть'}
    elif ogi or ogt:
        c['og'] = {'s': 'warn', 't': 'Нет картинки для превью ссылки' if not ogi else 'Нет заголовка для превью ссылки'}
    else:
        c['og'] = {'s': 'bad', 't': 'Превью не настроено – ссылка в мессенджере будет без картинки'}
    if re.search(r'mc\.yandex\.(ru|com)/(metrika|watch)|ym\(\s*\d', low):
        c['metrika'] = {'s': 'ok', 't': 'Яндекс Метрика установлена'}
    elif 'googletagmanager' in low:
        c['metrika'] = {'s': 'warn', 't': 'Метрику не нашли, но есть Google Tag Manager – она может грузиться через него'}
    else:
        c['metrika'] = {'s': 'warn', 't': 'Яндекс Метрику не нашли – посетители и заявки не считаются'}

    for k in ('offer', 'cta'):
        c[k] = {'s': 'skip', 't': 'Этот пункт появится позже'}
    return c, final


def mb(b):
    return f'{b / 1048576:.1f}'.replace('.', ',') + ' МБ' if b >= 1048576 else f'{round(b / 1024)} КБ'


def speed(url):
    """Замер скорости на телефоне через Google PageSpeed Insights (20–40 с). Ключ – в переменной окружения функции."""
    import os, urllib.request, urllib.parse
    key = os.environ.get('GOOGLE_PSI_KEY')
    if not key:
        raise CheckError('Замер скорости временно недоступен')
    safe_host(urlsplit(url).hostname)
    q = urllib.parse.urlencode([('url', url), ('strategy', 'mobile'), ('category', 'performance'),
                                ('category', 'accessibility'), ('locale', 'ru'), ('key', key)])
    try:
        with urllib.request.urlopen('https://www.googleapis.com/pagespeedonline/v5/runPagespeed?' + q, timeout=55) as r:
            j = json.load(r)
    except Exception:
        raise CheckError('Google не смог замерить скорость этого сайта')
    a = j.get('lighthouseResult', {}).get('audits', {})
    score = j.get('lighthouseResult', {}).get('categories', {}).get('performance', {}).get('score')
    c = {}
    lcp = (a.get('largest-contentful-paint') or {}).get('numericValue')
    if lcp is not None:
        s = lcp / 1000
        sec = f'{s:.1f}'.replace('.', ',')
        tail = f' (оценка Google – {round(score * 100)} из 100)' if score is not None else ''
        c['speed'] = {'s': 'ok' if s <= 2.5 else 'warn' if s <= 4 else 'bad',
                      't': f'Главное видно через {sec} с' + ('' if s <= 2.5 else ' – часть клиентов уйдёт раньше') + tail}
    w = (a.get('total-byte-weight') or {}).get('numericValue')
    if w is not None:
        c['weight'] = {'s': 'ok' if w <= 2 * 1048576 else 'warn' if w <= 5 * 1048576 else 'bad',
                       't': f'Страница весит {mb(w)}' + ('' if w <= 2 * 1048576 else ' – на мобильном интернете это долго')}
    img = a.get('image-delivery-insight') or {}
    if img:
        # экономия = сумма wastedBytes по картинкам (в Lighthouse 13 общего поля overallSavingsBytes нет)
        save = sum(i.get('wastedBytes') or 0 for i in (img.get('details') or {}).get('items') or [])
        c['img'] = {'s': 'ok', 't': 'Картинки уже хорошо сжаты'} if save < 200 * 1024 else \
            {'s': 'warn' if save < 1048576 else 'bad', 't': f'Фото можно сжать на {mb(save)} без потери качества'}
    ts = (a.get('target-size') or {}).get('score')
    if ts is not None:
        c['tap'] = {'s': 'ok', 't': 'По кнопкам и ссылкам легко попасть пальцем'} if ts >= 0.9 else \
            {'s': 'warn', 't': 'Часть кнопок или ссылок слишком мелкие или стоят вплотную'}
    for k in ('speed', 'weight', 'img', 'tap'):
        c.setdefault(k, {'s': 'skip', 't': 'Google не вернул этот замер'})
    return c


def handler(event, context):
    if (event or {}).get('httpMethod') == 'OPTIONS':
        return {'statusCode': 204, 'headers': CORS, 'body': ''}
    q = (event or {}).get('queryStringParameters') or {}
    try:
        url = norm(q.get('url'))
        if q.get('part') == 'speed':
            out, code = {'url': url, 'checks': speed(url)}, 200
            return {'statusCode': code, 'headers': CORS, 'body': json.dumps(out, ensure_ascii=False)}
        checks, final = run(url)
        out, code = {'url': url, 'final': final, 'checks': checks}, 200
    except CheckError as e:
        out, code = {'error': str(e)}, 400
    except Exception:
        out, code = {'error': 'Не удалось проверить сайт'}, 500
    return {'statusCode': code, 'headers': CORS, 'body': json.dumps(out, ensure_ascii=False)}
