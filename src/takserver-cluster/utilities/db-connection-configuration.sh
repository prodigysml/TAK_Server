#!/bin/bash

FILE=CoreConfig.xml

if [ ! -f "$FILE" ]; then
    FILE=opt/tak/CoreConfig.xml
fi

if [ -z "$DB_URL" ]; then
  DB_URL='jdbc:postgresql://takserver-postgresql:5432/cot'
fi

# No default credentials: postgres/postgres is the first thing anyone tries.
if [ -z "$DB_USERNAME" ] || [ -z "$DB_PASSWORD" ]; then
  echo "DB_USERNAME and DB_PASSWORD must be set." >&2
  exit 1
fi

# Escape for the XML attribute, then for the sed replacement, so a value
# containing & " < / | or \ can't break out and rewrite the rest of CoreConfig.xml.
sed_escape() {
  printf '%s' "$1" \
    | sed -e 's/&/\&amp;/g' -e 's/"/\&quot;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
    | sed -e 's/[\\/&|]/\\&/g'
}

sed -r -i "$FILE" -e "s|DB_URL_PLACEHOLDER|$(sed_escape "$DB_URL")|g"
sed -r -i "$FILE" -e "s|DB_USERNAME_PLACEHOLDER|$(sed_escape "$DB_USERNAME")|g"
sed -r -i "$FILE" -e "s|DB_PASSWORD_PLACEHOLDER|$(sed_escape "$DB_PASSWORD")|g"
