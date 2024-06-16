import logging

from rich.console import Console
from rich.logging import RichHandler

# Setting up logging with rich
FORMAT = "%(message)s"
logging.basicConfig(level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()])

log = logging.getLogger("rich")

# Initializing console for rich
console = Console()


class Output:
    def __init__(self, output_type, result, info, outputinfo) -> None:
        self.output_type = output_type
        self.result = result
        self.info = info
        self.outputinfo = outputinfo

    def output(self) -> None:
        if self.output_type == "gophish":
            self.gophish()
        elif self.output_type == "txt":
            self.txt()
        elif self.output_type == "stdout":
            self.stdout()

    def stdout(self) -> None:
        if self.info == "email":
            for user in self.result:
                console.print(user["email"])
        elif self.info == "name":
            for user in self.result:
                console.print(user["name"])
        elif self.info == "title":
            for user in self.result:
                console.print(user["title"])

    def gophish(self) -> None:
        with open(self.outputinfo, "w") as f:
            f.write("First Name,Last Name,Position,Email")
            for user in self.result:
                if len(user["name"].split(" ")) == 3 and user["name"].split(" ")[2]:
                    f.write(
                        f'{user["name"].split(" ")[0]},{user["name"].split(" ")[2]},{user["title"]},{user["email"]}\n'
                    )
                elif len(user["name"].split(" ")) == 2 and user["name"].split(" ")[1]:
                    f.write(
                        f'{user["name"].split(" ")[0]},{user["name"].split(" ")[1]},{user["title"]},{user["email"]}\n'
                    )
                else:
                    log.info(f"{user['name']} has no last name")

    def txt(self) -> None:
        with open(self.outputinfo, "w") as f:
            if self.info == "email":
                for user in self.result:
                    f.write(f"{user['email'].lower()}\n")
            elif self.info == "name":
                for user in self.result:
                    f.write(f"{user['name']}\n")
            elif self.info == "title":
                for user in self.result:
                    f.write(f"{user['title']}\n")
