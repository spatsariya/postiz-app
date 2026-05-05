import { google } from 'googleapis';
import {
  AuthProvider,
  AuthProviderAbstract,
} from '@gitroom/backend/services/auth/providers.interface';

const defaultRedirect = () =>
  process.env.GOOGLE_REDIRECT_URI ||
  `${process.env.FRONTEND_URL}/integrations/social/youtube`;

const getGoogleCredentials = () => {
  const clientId = process.env.GOOGLE_CLIENT_ID || process.env.YOUTUBE_CLIENT_ID;
  const clientSecret =
    process.env.GOOGLE_CLIENT_SECRET || process.env.YOUTUBE_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error(
      'Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET (or YOUTUBE_CLIENT_ID and YOUTUBE_CLIENT_SECRET).'
    );
  }

  return { clientId, clientSecret };
};

const makeClient = (redirectUri: string) =>
  new google.auth.OAuth2({
    ...getGoogleCredentials(),
    redirectUri,
  });

@AuthProvider({ provider: 'GOOGLE' })
export class GoogleProvider extends AuthProviderAbstract {
  generateLink(query?: { redirect_uri?: string }) {
    const redirectUri = query?.redirect_uri || defaultRedirect();
    return makeClient(redirectUri).generateAuthUrl({
      access_type: 'online',
      prompt: 'consent',
      state: 'login',
      redirect_uri: redirectUri,
      scope: [
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email',
      ],
    });
  }

  async getToken(code: string, redirectUri?: string) {
    const client = makeClient(redirectUri || defaultRedirect());
    const { tokens } = await client.getToken(code);
    return tokens.access_token!;
  }

  async getUser(providerToken: string) {
    const client = makeClient(defaultRedirect());
    client.setCredentials({ access_token: providerToken });
    const { data } = await google
      .oauth2({ version: 'v2', auth: client })
      .userinfo.get();

    return {
      id: data.id!,
      email: data.email!,
    };
  }
}
