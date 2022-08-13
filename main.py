"""Script that combines multiple adjacent and main words with some domain extensions.\
And seek for whois information. Those domains that has expiration date are stored in output file."""
import itertools

import whois
from progress.bar import ShadyBar

PRINT_FOUND_ONLY = True

main_word = [
    "awesome",
]

adj_words = [
    "",
    "card",
    "cards",
    "bank",
    "credit",
    "pay",
    "terminal",
    "debit",
    "loans",
    "business",
    "capital",
]

tld = [
    "com",
    "org",
    "net",
    "mx",
    "finance",
]


combinations = list(itertools.product(adj_words, main_word, adj_words)) + list(
    itertools.product(adj_words, ["-"], main_word, ["-"], adj_words)
)
clean_combinations = [c for c in combinations if c[0] != c[-1]]
possible_domains = list(itertools.product(["".join(name) for name in clean_combinations], tld))
cleaned_domains = [".".join(domain) for domain in possible_domains]

bar = ShadyBar("Processing", max=len(cleaned_domains), suffix="%(index)d/%(max)d - %(percent).1f%% - ETA: %(eta)ds.")

found_list = []
found_counter = 0

for domain in cleaned_domains:
    if domain[0] != "-" or domain[-1] != "-":
        bar.next()
        # print(domain)
        try:
            w = whois.whois(domain)
        except whois.parser.PywhoisError as e:
            # print(domain, e)
            pass
        else:
            has_expiration = bool(w.expiration_date is not None)
            if PRINT_FOUND_ONLY:
                if has_expiration:
                    found_counter += 1
                    expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                    found_list.append((domain, expiration_date))
            else:
                found_list.append((domain, w.expiration_date))

bar.finish()

with open("output", "w+", encoding="utf-8") as output:
    print(f"Registered domains: {found_counter}")
    for f in found_list:
        output.write(f"{f[0]} - {f[1]}\n")
        print(f"{f[0]}. Expiration date: {f[1].strftime('%Y-%m-%d')}")
