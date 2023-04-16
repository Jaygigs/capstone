FROM node:16-alpine


COPY package*.json .


RUN npm install

RUN npm install -g react-script

RUN npm install nodemon

COPY . .

EXPOSE 3000

CMD ["npm","start"]