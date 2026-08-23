# Read .env the way docker compose does, for the scripts that run on the host.
#
# Sourced rather than copied into each script: the same rule implemented in several places is
# the drift this project keeps having to fix. scripts/_dotenv.py is its Python twin
# and must follow the same rules.
#
# No eval, and the key whitelist is genuinely anchored. Two subtleties cost us a real
# command injection here, both worth spelling out:
#
#   1. In a `case` pattern, `*` matches ANY string, not "more of the preceding class".
#      So `[A-Za-z_][A-Za-z0-9_]*` constrains only the first two characters, and
#      `ab[$(cmd)]` sails through it. The negated bracket below is what actually
#      anchors: a key containing any character outside the identifier set is rejected.
#   2. Bash indirect expansion `${!k}` treats a value shaped like `name[subscript]` as
#      an array reference and evaluates the subscript arithmetically, which performs
#      command substitution. So an unvalidated key reaches code execution even with no
#      eval anywhere in sight.
#
# An exported variable always wins, so this only fills in what the shell has not set.
vo_load_dotenv() {
  [ -f .env ] || return 0
  local k v
  # `|| [ -n "$k" ]` so a final line with no trailing newline is still read.
  while IFS='=' read -r k v || [ -n "$k" ]; do
    case "$k" in
      ""|\#*|*[!A-Za-z0-9_]*|[0-9]*) continue;;
    esac
    v="${v%%[[:space:]]#*}"; v="${v%"${v##*[![:space:]]}"}"
    # compose strips one layer of matching surrounding quotes; match that.
    case "$v" in
      \"*\") v="${v:1:${#v}-2}";;
      \'*\') v="${v:1:${#v}-2}";;
    esac
    [ -n "${!k-}" ] || export "$k=$v"
  done < .env
}
