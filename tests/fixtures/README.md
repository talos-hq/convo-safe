# PII fixture provenance

The UTF-8 TSV is a compact, offline corpus. Each sensitive row names its
expected kind, the exact span, and a template containing one {value}.
KEEP rows must survive unchanged with email redaction enabled.

- Five sandbox PANs, three sandbox ACH values, and a sandbox email alias are from the Stripe testing
  tables, including Diners 14 digits, UnionPay 19 digits. PAN separators and failed checksums are derived here.
  https://docs.stripe.com/testing
- ABA length, district prefixes and checksum handling follow the Federal
  Reserve check specification. The account detector requires explicit
  banking context, as a shape alone is ambiguous.
  https://www.frbservices.org/binaries/content/assets/crsocms/financial-services/check/setup/frb-x937-standards-reference.pdf
  https://github.com/data-privacy-stack/presidio/blob/main/docs/supported_entities.md
- Phone fixtures adapt matcher cases from libphonenumber for extensions,
  punctuation and dates. Example phone numbers use fictional ranges.
  https://github.com/google/libphonenumber/blob/master/java/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberMatcherTest.java
- Email fixtures adapt Apache Commons Validator cases for aliases, embedded
  apostrophes and malformed labels. Domains are examples, and the test is
  for text-span detection rather than mail delivery.
  https://github.com/apache/commons-validator/blob/master/src/test/java/org/apache/commons/validator/routines/EmailValidatorTest.java

Upstream test sources were downloaded for selection. The gate uses only this
small reviewed corpus, with no downloads or external model requests.
