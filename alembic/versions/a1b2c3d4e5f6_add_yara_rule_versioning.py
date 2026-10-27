"""add_yara_rule_versioning (M02B, Phase 1)"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
import hashlib
import sys


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '5655c33dba69'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def table_exists(connection, table_name: str) -> bool:
    result = connection.execute(text("""\
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name=:tn
    """), {"tn": table_name})
    return result.fetchone() is not None


def column_exists(connection, table_name: str, column_name: str) -> bool:
    rows = connection.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    return any(row[1] == column_name for row in rows)


def index_exists(connection, index_name: str) -> bool:
    result = connection.execute(text("""\
        SELECT name FROM sqlite_master 
        WHERE type='index' AND name=:ix
    """), {"ix": index_name})
    return result.fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not table_exists(conn, 'yara_rule_versions'):
        op.create_table(
            'yara_rule_versions',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('rule_id', sa.Integer(), sa.ForeignKey('yara_rules.id', ondelete='CASCADE'), nullable=False),
            sa.Column('version', sa.Integer(), nullable=False),
            sa.Column('source', sa.Text(), nullable=False),
            sa.Column('source_hash', sa.String(64), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('author', sa.String(128), nullable=True),
            sa.Column('tags', sa.Text(), nullable=True),
            sa.Column('severity', sa.String(32), nullable=True),
            sa.Column('category', sa.String(64), nullable=True),
            sa.Column('published_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('published_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.Column('is_published', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        )
        op.create_index(op.f('ix_yara_rule_versions_rule_id'), 'yara_rule_versions', ['rule_id'], unique=False)
        op.create_index(op.f('ix_yara_rule_versions_rule_version'), 'yara_rule_versions', ['rule_id', 'version'], unique=True)

    if not table_exists(conn, 'yara_matches'):
        op.create_table(
            'yara_matches',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('sample_id', sa.Integer(), sa.ForeignKey('samples.id', ondelete='CASCADE'), nullable=False),
            sa.Column('rule_name', sa.String(128), nullable=False),
            sa.Column('namespace', sa.String(64), nullable=False, server_default='default'),
            sa.Column('tags', sa.String(255), nullable=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        )
        op.create_index(op.f('ix_yara_matches_sample_id'), 'yara_matches', ['sample_id'], unique=False)
        op.create_index(op.f('ix_yara_matches_rule_name'), 'yara_matches', ['rule_name'], unique=False)

    if not column_exists(conn, 'yara_matches', 'rule_version_id'):
        conn.execute(text("""\
            ALTER TABLE yara_matches ADD COLUMN rule_version_id INTEGER
                REFERENCES yara_rule_versions(id) ON DELETE RESTRICT
        """))
        if not index_exists(conn, 'ix_yara_matches_rule_version'):
            op.create_index(op.f('ix_yara_matches_rule_version'), 'yara_matches', ['rule_version_id'], unique=False)

    if not column_exists(conn, 'yara_rules', 'current_version_id'):
        conn.execute(text("""\
            ALTER TABLE yara_rules ADD COLUMN current_version_id INTEGER
                REFERENCES yara_rule_versions(id) ON DELETE SET NULL
        """))

    seeded = conn.execute(text("SELECT COUNT(*) FROM yara_rule_versions")).scalar()
    if seeded == 0:
        rules = conn.execute(text("SELECT id, source, version, tags, description, author FROM yara_rules")).fetchall()
        for rule in rules:
            rule_id, source, version, tags, description, author = rule
            source = source or ''
            result = conn.execute(text("""\
                INSERT INTO yara_rule_versions
                    (rule_id, version, source, source_hash, description, author, tags,
                     severity, category, published_by, published_at, is_published)
                VALUES
                    (:rule_id, :version, :source, :source_hash, :description, :author, :tags,
                     NULL, NULL, NULL, CURRENT_TIMESTAMP, 1)
            """), {
                'rule_id': rule_id,
                'version': version or 1,
                'source': source,
                'source_hash': hashlib.sha256(source.encode('utf-8')).hexdigest(),
                'description': description,
                'author': author,
                'tags': tags,
            })
            conn.execute(text("""\
                UPDATE yara_rules SET current_version_id = :vid WHERE id = :rid
            """), {'vid': result.lastrowid, 'rid': rule_id})


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(text("DROP INDEX IF EXISTS ix_yara_matches_rule_version"))
    conn.execute(text("ALTER TABLE yara_matches DROP COLUMN rule_version_id"))
    conn.execute(text("ALTER TABLE yara_rules DROP COLUMN current_version_id"))
    conn.execute(text("DROP INDEX IF EXISTS ix_yara_rule_versions_rule_version"))
    conn.execute(text("DROP INDEX IF EXISTS ix_yara_rule_versions_rule_id"))
    conn.execute(text("DROP TABLE IF EXISTS yara_rule_versions"))