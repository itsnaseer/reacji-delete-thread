const { App } = require('@slack/bolt');

const app = new App({
  token: process.env.SLACK_BOT_TOKEN,
  signingSecret: process.env.SLACK_SIGNING_SECRET
});

app.event('reaction_added', async ({ event, client }) => {
  if (event.reaction === 'specific_reaction') {
    try {
      // Delete the original message
      await client.chat.delete({
        channel: event.item.channel,
        ts: event.item.ts
      });

      // Fetch and delete all threaded replies
      const replies = await client.conversations.replies({
        channel: event.item.channel,
        ts: event.item.ts
      });

      for (const reply of replies.messages) {
        await client.chat.delete({
          channel: event.item.channel,
          ts: reply.ts
        });
      }
    } catch (error) {
      console.error(error);
    }
  }
});

(async () => {
  await app.start(process.env.PORT || 3000);
  console.log('⚡️ Bolt app is running!');
})();
