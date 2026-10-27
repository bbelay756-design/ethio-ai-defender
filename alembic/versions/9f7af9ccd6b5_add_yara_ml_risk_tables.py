"""add_yara_ml_risk_tables

Revision ID: 9f7af9ccd6b5
Revises: 4873db075a39
Create Date: 2026-10-23 00:32:27.019359

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '9f7af9ccd6b5'
down_revision: Union[str, None] = '4873db075a39'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def table_exists(connection, table_name: str) -> bool:
    """Check if a table exists in the database."""
    result = connection.execute(text(f"""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='{table_name}'
    """))
    return result.fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    
    # YARA Rules table
    if not table_exists(conn, 'yara_rules'):
        op.create_table(
            'yara_rules',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('name', sa.String(255), unique=True, nullable=False, index=True),
            sa.Column('namespace', sa.String(64), nullable=False, default='default'),
            sa.Column('source', sa.Text(), nullable=False),
            sa.Column('compiled', sa.LargeBinary(), nullable=True),
            sa.Column('version', sa.Integer(), nullable=False, default=1),
            sa.Column('tags', sa.Text(), nullable=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('author', sa.String(128), nullable=True),
            sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
        )
        op.create_index(op.f('ix_yara_rules_namespace'), 'yara_rules', ['namespace'], unique=False)
        op.create_index(op.f('ix_yara_rules_is_active'), 'yara_rules', ['is_active'], unique=False)

    # ML Models table
    if not table_exists(conn, 'ml_models'):
        op.create_table(
            'ml_models',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('name', sa.String(255), unique=True, nullable=False),
            sa.Column('version', sa.String(64), nullable=False),
            sa.Column('model_type', sa.String(64), nullable=False),
            sa.Column('feature_version', sa.String(32), nullable=False),
            sa.Column('model_path', sa.String(512), nullable=False),
            sa.Column('feature_schema_hash', sa.String(64), nullable=False),
            sa.Column('metrics', sa.Text(), nullable=True),
            sa.Column('is_active', sa.Boolean(), nullable=False, default=False),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column('deployed_at', sa.DateTime(), nullable=True),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        )
        op.create_index(op.f('ix_ml_models_is_active'), 'ml_models', ['is_active'], unique=False)

    # ML Predictions table
    if not table_exists(conn, 'ml_predictions'):
        op.create_table(
            'ml_predictions',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('sample_id', sa.Integer(), sa.ForeignKey('samples.id', ondelete='CASCADE'), nullable=False),
            sa.Column('model_id', sa.Integer(), sa.ForeignKey('ml_models.id', ondelete='SET NULL'), nullable=True),
            sa.Column('prediction', sa.Integer(), nullable=False),
            sa.Column('probability', sa.Float(), nullable=False),
            sa.Column('feature_vector', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )

    # Risk Configurations table
    if not table_exists(conn, 'risk_configs'):
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

    # Ghidra Decompilations table
    if not table_exists(conn, 'ghidra_decompilations'):
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
    op.drop_table('ml_predictions')
    op.drop_table('ml_models')
    op.drop_table('yara_rules')