#!/usr/bin/env python3

import json
import logging

import click
from rich.console import Console
from rich.logging import RichHandler

from .lib.output import Output

# Setting up logging with rich
FORMAT = "%(message)s"
logging.basicConfig(level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()])

log = logging.getLogger("rich")

# Initializing console for rich
console = Console()


def parse_userfile(userfile):
    """
    Parses the userfile and returns a list of users.
    """

    userdat = []

    with open(userfile, "r") as f:
        users = json.load(f)

        try:
            if users["data"]:
                key = "data"
        except KeyError:
            key = "users"

        for user in users[key]:
            singleuser = {}
            try:
                if (
                    user["Properties"]["email"]
                    and len(user["Properties"]["email"].split("@")[0]) < 25
                ):
                    if user["Properties"]["email"]:
                        email = user["Properties"]["email"]
                        singleuser["email"] = email
                    if user["Properties"]["displayname"]:
                        name = user["Properties"]["displayname"]
                        singleuser["name"] = name
                    if user["Properties"]["title"]:
                        title = user["Properties"]["title"]
                        singleuser["title"] = title
                    else:
                        title = "None"
                        singleuser["title"] = title

                    userdat.append(singleuser)

            except KeyError:
                pass

    return userdat


# Setting context settings for click
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help", "help"])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    """
    Parse BloodHound JSON userfiles for external use.
    """
    pass


@cli.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@click.argument("userfile", type=click.Path(exists=True))
@click.argument("outputinfo", type=click.Path(exists=False), default="output.csv")
def gophish(userfile, outputinfo):
    """
    Outputs a gophish import compatible csv file. \n

    Example: bhp gophish userfile.json gophish.csv\n

    Default output file is output.csv
    """

    userdat = parse_userfile(userfile)

    output = Output("gophish", userdat, "name", outputinfo)
    output.output()


@cli.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@click.argument(
    "info", type=click.Choice(["email", "name", "title"]), default="email", required=False
)
@click.argument("userfile", type=click.Path(exists=True))
def stdout(info, userfile):
    """
    Outputs specified type to stdout. \n

    Example: bhp stdout name userfile.json \n

    Default type is email.
    """
    userdat = parse_userfile(userfile)
    out = Output("stdout", userdat, info, outputinfo=None)
    out.output()


@cli.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@click.argument("userfile", type=click.Path(exists=True))
@click.argument("outputinfo", type=click.Path(exists=False), default="output.txt")
@click.argument(
    "info", type=click.Choice(["email", "name", "title"]), default="email", required=False
)
def txt(userfile, outputinfo, info):
    """
    Outputs specified type to a text file. \n

    Example: bhp txt title users.json output.txt \n

    Default type is email.
    """

    result = parse_userfile(userfile)
    out = Output("txt", result, info, outputinfo)
    out.output()


if __name__ == "__main__":
    cli()
