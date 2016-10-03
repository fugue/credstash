from __future__ import absolute_import, division, print_function

import click
from .cli import main
from .dynamodb_storage_service import DynamoDbStorageService


@main.command('setup-dynamodb')
@click.option('--read-capacity', type=click.INT, default=1)
@click.option('--write-capacity', type=click.INT, default=1)
@click.pass_context
def cmd_setup(ctx, read_capacity, write_capacity):
    """
    Setup the credential table in AWS DynamoDB
    """
    storage_service = ctx.obj.storage_service
    if not isinstance(storage_service, DynamoDbStorageService):
        raise click.ClickException('Cannot setup unknown storage service')
    storage_service.setup(
        read_capacity, write_capacity
    )

