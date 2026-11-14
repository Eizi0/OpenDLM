"""audit events

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-14 15:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('action', sa.String(length=120), nullable=False),
    sa.Column('params', sa.JSON(), nullable=False),
    sa.Column('outcome', sa.String(length=16), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_events_at'), 'audit_events', ['at'], unique=False)
    op.create_index(op.f('ix_audit_events_username'), 'audit_events', ['username'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_audit_events_username'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_at'), table_name='audit_events')
    op.drop_table('audit_events')
