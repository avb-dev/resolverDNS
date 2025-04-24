import argparse
from time import sleep

import dns.message
import dns.name
import dns.query
import dns.rdatatype
from dnslib import RR, QTYPE, A, AAAA
from dnslib.server import DNSServer, BaseResolver, DNSLogger


FORMATS = [("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}")]

ROOT_SERVERS = (
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33"
)

# In-memory domain cache
domain_cache = {}


def get_results(name: str) -> dict:
    """Запрашивает A и AAAA записи у корневых серверов."""
    full_response = {"A": [], "AAAA": []}
    target_name = dns.name.from_text(name)

    for record_type, rdatatype in [("A", dns.rdatatype.A), ("AAAA", dns.rdatatype.AAAA)]:
        response = find(target_name, rdatatype)
        if response and response.answer:
            for answers in response.answer:
                for answer in answers:
                    if answer.rdtype == rdatatype:
                        full_response[record_type].append({
                            "name": str(answers.name),
                            "address": str(answer)
                        })

    return full_response


def find(target_name: dns.name.Name, qtype: int) -> dns.message.Message:
    """Пытается найти запись, начиная с корневых серверов."""
    domain = get_domain_key(target_name)

    if domain not in domain_cache:
        domain_cache[domain] = {}

    for root_server in ROOT_SERVERS:
        if root_server in domain_cache[domain]:
            response = domain_cache[domain][root_server]
        else:
            response = make_request(target_name, qtype, root_server)
            domain_cache[domain][root_server] = response

        if response:
            if response.answer:
                return response
            elif response.additional:
                for additional in response.additional:
                    if additional.rdtype != dns.rdatatype.A:
                        continue
                    for add in additional:
                        new_response = find_recursive(target_name, qtype, str(add))
                        if new_response and new_response.answer:
                            return new_response
    return None


def make_request(target_name: dns.name.Name, qtype: int, ip_addr: str) -> dns.message.Message:
    """Отправляет DNS-запрос на указанный IP."""
    query = dns.message.make_query(target_name, qtype)
    try:
        response = dns.query.udp(query, ip_addr, timeout=3)
    except Exception as e:
        response = None
    return response


def find_recursive(target_name: dns.name.Name, qtype: int, ip_addr: str) -> dns.message.Message:
    """Рекурсивно пытается разрешить имя."""
    response = make_request(target_name, qtype, ip_addr)
    if not response:
        return None

    if response.answer:
        for answer in response.answer:
            if answer.rdtype == dns.rdatatype.CNAME and qtype != dns.rdatatype.CNAME:
                cname_target = dns.name.from_text(str(answer[0]))
                return find(cname_target, qtype)
        return response
    elif response.additional:
        for additional in response.additional:
            if additional.rdtype != dns.rdatatype.A:
                continue
            for add in additional:
                new_response = find_recursive(target_name, qtype, str(add))
                if new_response and new_response.answer:
                    return new_response
    return response


def get_domain_key(name: dns.name.Name) -> str:
    """Извлекает ключ домена для кэширования."""
    labels = name.labels
    if len(labels) < 2:
        return str(name)
    return labels[-2].decode()


def print_results(results: dict) -> None:
    """Форматированный вывод результатов."""
    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


class DNSResolver(BaseResolver):
    """Реализация собственного резолвера."""

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname)
        result = get_results(qname)

        for rec in result["A"]:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(rec["address"]), ttl=60))
        for rec in result["AAAA"]:
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(rec["address"]), ttl=60))

        print(f"Запрос: {qname}")
        print_results(result)

        return reply


def main():
    parser = argparse.ArgumentParser(description="DNS-сервер с рекурсией")
    parser.add_argument("--host", default="localhost", help="IP-адрес для прослушивания")
    parser.add_argument("--port", type=int, default=5354, help="Порт для прослушивания")
    args = parser.parse_args()

    resolver = DNSResolver()
    logger = DNSLogger(prefix=False)
    server = DNSServer(resolver, port=args.port, address=args.host, logger=logger)

    print(f"Сервер запущен на {args.host}:{args.port}")
    server.start_thread()

    try:
        while server.isAlive():
            sleep(1)
    except KeyboardInterrupt:
        print("\nСервер остановлен.")


if __name__ == "__main__":
    main()