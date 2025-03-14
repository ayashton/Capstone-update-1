"""Re-sync database with existing schema

Revision ID: 4373ea0cc149
Revises: 
Create Date: 2025-03-07 10:31:24.356295

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '4373ea0cc149'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('stocks', schema=None) as batch_op:
        batch_op.create_unique_constraint(None, ['symbol'])
        batch_op.drop_column('initial_price')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('stocks', schema=None) as batch_op:
        batch_op.add_column(sa.Column('initial_price', mysql.FLOAT(), nullable=False))
        batch_op.drop_constraint(None, type_='unique')

    # ### end Alembic commands ###
