import JWT from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { NotAuthorizedError } from './error-handler';

const tokens: string[] = [
  'auth',
  'seller',
  'gig',
  'search',
  'buyer',
  'message',
  'order',
  'review',
];

export function verifyGatewayRequest(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.headers?.gatewayToken) {
    throw new NotAuthorizedError(
      'Invalid request',
      'verifyGatewayRequest() method: Request not coming from API Gateway'
    );
  }

  const token: string = req.headers.gatewayToken as string;

  try {
    const payload = JWT.verify(token, '') as {
      id: string;
      iat: number;
    };
    if (!tokens.includes(payload.id)) {
      throw new NotAuthorizedError(
        'Invalid request',
        'verifyGatewayRequest() method: Request payload is not valid'
      );
    }
  } catch (error) {
    throw new NotAuthorizedError(
      'Invalid request',
      'verifyGatewayRequest() method: Request not coming from API Gateway'
    );
  }
}
