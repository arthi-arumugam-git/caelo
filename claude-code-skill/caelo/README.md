# Caelo skill for Claude Code

A Claude Code skill that runs Caelo, a free and local developer security scanner, against the project you are working in and explains the results.

## What it does

When you ask Claude Code for a security check (for example before shipping, or when you are worried about leaked API keys or an open database), this skill has Claude run `npx -y caelo .` in your project root, read Caelo's graded report, and summarize the findings and fixes in plain language.

## Install

Claude Code loads skills from a `skills` directory. Copy the whole `caelo` folder into one of these:

- Personal, available in every project:

  ```
  ~/.claude/skills/caelo/
  ```

  On Windows that is `C:\Users\<you>\.claude\skills\caelo\`.

- Project only, available in one project:

  ```
  <your-project>/.claude/skills/caelo/
  ```

After copying, you should have the file at `.../skills/caelo/SKILL.md`. Start a new Claude Code session so it picks up the skill. Claude loads it on its own when a request matches, or you can ask for it by name.

## Requirements

- Node.js and npm, which provide the `npx` command that Caelo runs through.
- No account and no API key. Caelo runs locally, reads files only, and uploads nothing.

## Links

- Homepage: https://caelo.sh
- Source (MIT): https://github.com/arthi-arumugam-git/caelo
- Made by Irth Labs: https://www.irthlabs.com
