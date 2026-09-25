FROM public.ecr.aws/amazonlinux/amazonlinux:2023 AS deps

# Install Node.js and npm
RUN dnf clean all && dnf -y update && \
    curl -fsSL https://rpm.nodesource.com/setup_22.x | bash - && \
    dnf -y install nodejs && \
    dnf clean all

WORKDIR /app

# Install all deps
# Copy package.json to the /app working directory
COPY package*.json tsconfig.json .env dmptool-*.tgz ./

# Install dependencies in /app
RUN npm ci

# Copy the rest of our Apollo Server folder into /app
COPY . .

# Ensure port 4646 is accessible to our system
EXPOSE 4646

# Command to run the Next.js app in development mode
CMD ["npm", "run", "dev"]
