"""add_analyst_reviews_table (ML-13)

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-28 23:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def table_exists(connection, table_name: str) -> bool:
    result = connection.execute(
        text("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name=:tn
    """),
        {"tn": table_name}
    )
    return result.fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not table_exists(conn, 'analyst_reviews'):
        op.create_table(
            'analyst_reviews',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('sample_id', sa.Integer(), sa.ForeignKey('samples.id', ondelete='CASCADE'), nullable=False),
            sa.Column('analysis_id', sa.String(64), nullable=False),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('reviewer_username', sa.String(64), nullable=False),
            sa.Column('verdict', sa.String(32), nullable=False),
            sa.Column('review_state', sa.String(32), nullable=False),
            sa.Column('previous_state', sa.String(32), nullable=False, server_default='PENDING_REVIEW'),
            sa.Column('rationale', sa.Text(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(op.f('ix_analyst_reviews_sample_id'), 'analyst_reviews', ['sample_id'], unique=False)
        op.create_index(op.f('ix_analyst_reviews_analysis_id'), 'analyst_reviews', ['analysis_id'], unique=True)
        op.create_index(op.f('ix_analyst_reviews_user_id'), 'analyst_reviews', ['user_id'], unique=False)
        op.create_index(op.f('ix_analyst_reviews_created_at'), 'analyst_reviews', ['created_at'], unique=False)


def downgrade() -> None:
    conn = op.get_bind()
    if table_exists(conn, 'analyst_reviews'):
        op.drop_table('analyst_reviews')
