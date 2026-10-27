"""add_missing_risk_ghidra_tables

Revision ID: 5655c33dba69
Revises: 9f7af9ccd6b5
Create Date: 2026-10-23 00:37:46.836663

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5655c33dba69'
down_revision: Union[str, None] = '9f7af9ccd6b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # Risk Configurations table
    # (also created - guarded - by 9f7af9ccd6b5; guard here so a fresh
    # database can run the full chain: 9f7 -> 5655 -> ...)
    if conn.execute(sa.text(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='risk_configs'"
    )).fetchone() is None:
        op.create_table(
            'risk_configs',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('name', sa.String(128), unique=True, nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('weights', sa.Text(), nullable=False),
            sa.Column('thresholds', sa.Text(), nullable=False),
            sa.Column('category_caps', sa.Text(), nullable=True),
            sa.Column('is_default', sa.Boolean(), nullable=False, default=False),
            sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        )
        op.create_index(op.f('ix_risk_configs_is_active'), 'risk_configs', ['is_active'], unique=False)

    # Ghidra Decompilations table (also created - guarded - by 9f7af9ccd6b5)
    if conn.execute(sa.text(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='ghidra_decompilations'"
    )).fetchone() is None:
        op.create_table(
            'ghidra_decompilations',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('sample_id', sa.Integer(), sa.ForeignKey('samples.id', ondelete='CASCADE'), unique=True, nullable=False),
            sa.Column('function_count', sa.Integer(), nullable=False, default=0),
            sa.Column('decompiled_functions', sa.Text(), nullable=True),
            sa.Column('call_graph', sa.Text(), nullable=True),
            sa.Column('cross_references', sa.Text(), nullable=True),
            sa.Column('analysis_time_ms', sa.Integer(), nullable=True),
            sa.Column('ghidra_version', sa.String(64), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )


def downgrade() -> None:
    op.drop_table('ghidra_decompilations')
    op.drop_table('risk_configs')