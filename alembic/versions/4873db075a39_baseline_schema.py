"""baseline_schema

Revision ID: 4873db075a39
Revises: 
Create Date: 2026-10-23 00:32:13.220078

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4873db075a39'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Baseline migration - the database schema already exists from init_db()
    # This migration just creates the alembic_version table to mark the baseline
    pass


def downgrade() -> None:
    # Baseline migration cannot be downgraded
    pass