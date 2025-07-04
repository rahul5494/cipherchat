# Use a lightweight Node.js base image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the port your app uses (replace 3000 with your app's port)
EXPOSE 3000

# Command to run the app
CMD ["npm", "start"]
