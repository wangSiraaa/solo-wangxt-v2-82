package store

import (
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// dbNameFromDSN 解析 DSN 中的数据库名(支持 URL 与 keyword 两种形式)。
func dbNameFromDSN(dsn string) string {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return ""
	}
	return cfg.ConnConfig.Database
}

// pgIdentifier 校验标识符只含安全字符,防止拼接建库语句时注入。
func pgIdentifier(s string) string {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			panic("非法数据库标识符: " + s)
		}
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
