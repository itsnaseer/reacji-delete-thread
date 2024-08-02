# Slack App

### Delete Messages
Use this app to delete messages (+ threaded replies) and generate the user token `(xoxp-1234567890)` for your current user.

### Clear Channel History
If you want to clear a channel's entire history, use the /clear-channel command.
Deleting messages cannot be reversed unless you have fine-tuned your retention settings.

### Get Started
This app uses a combination of bot and user token scopes to get permissions to manage conversations (DM, Channel, MPDM). The app uses the current user’s ID to generate the token. After generating the token it will send a message to the App’s Messages tab.
1. Set up. Add delete-thread as a reaction in your workspace. I like this version, but you can use your own.
2. Test.Find a message anywhere in your workspace and apply the :delete-thread: reaction. If there are threaded messages, all replies will delete.
3. (optional) Copy your token. If you are using Smockbot Next, go to the your user’s DM with themself, copy the token, and follow the instructions for Using with SBN.
4. Delete the token message. Find the direct message  with your user’s token in the DM with yourself and delete the message with the user token.
*Bonus points*. Use :delete-thread: to delete the DM with the token info.

<Install URL|https://slack.com/oauth/v2/authorize?client_id=1136833012721.7175339828356&scope=channels:history,channels:read,chat:write,groups:history,groups:read,im:history,im:read,mpim:history,mpim:read,reactions:read,commands&user_scope=admin,channels:history,channels:read,chat:write,reactions:read,admin.conversations:write,mpim:history,groups:history,im:history>

Are you looking for more comprehensive guidance? Check out the App Canvas in Giant Speck
