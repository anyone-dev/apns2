import { EventEmitter } from 'events'
import { Errors } from './errors'
import { Notification, Priority } from './notifications/notification'
import * as jose from 'jose'

// APNS version
const API_VERSION = 3

// Signing algorithm for JSON web token
const SIGNING_ALGORITHM = 'ES256'

// Reset our signing token every 55 minutes as reccomended by Apple
const RESET_TOKEN_INTERVAL_MS = 55 * 60 * 1000

export enum Host {
  production = 'api.push.apple.com',
  development = 'api.sandbox.push.apple.com'
}

export interface SigningToken {
  value: string
  timestamp: number
}

export interface ApnsOptions {
  team: string
  signingKey: string
  keyId: string
  defaultTopic?: string
  host?: Host | string
  requestTimeout?: number
  pingInterval?: number
}

export class ApnsClient extends EventEmitter {
  readonly team: string
  readonly keyId: string
  readonly host: Host | string
  readonly signingKey: string
  readonly defaultTopic?: string
  readonly requestTimeout?: number
  readonly pingInterval?: number

  private _token: SigningToken | null

  constructor(options: ApnsOptions) {
    super()
    this.team = options.team
    this.keyId = options.keyId
    this.signingKey = options.signingKey
    this.defaultTopic = options.defaultTopic
    this.host = options.host ?? Host.production
    this.requestTimeout = options.requestTimeout
    this.pingInterval = options.pingInterval
    this._token = null
    this.on(Errors.expiredProviderToken, () => this._resetSigningToken())
  }

  send(notification: Notification) {
    return this._send(notification)
  }

  sendMany(notifications: Notification[]) {
    const promises = notifications.map((notification) => {
      return this._send(notification).catch((error: any) => ({ error }))
    })
    return Promise.all(promises)
  }

  private async _send(notification: Notification) {
    const token = encodeURIComponent(notification.deviceToken)
    const url = `https://${this.host}/${API_VERSION}/device/${token}`
    const options: RequestInit = {
      method: 'POST',
      // @ts-ignore
      headers: {
        authorization: `bearer ${await this._getSigningToken()}`,
        'apns-push-type': notification.pushType,
        'apns-topic': notification.options.topic ?? this.defaultTopic
      },
      body: JSON.stringify(notification.buildApnsOptions()),
      timeout: this.requestTimeout,
      keepAlive: this.pingInterval ?? 5000
    }

    if (notification.priority !== Priority.immediate) {
      // @ts-ignore
      options.headers!['apns-priority'] = notification.priority.toString()
    }

    if (notification.options.expiration) {
      // @ts-ignore
      options.headers!['apns-expiration'] =
        typeof notification.options.expiration === 'number'
          ? notification.options.expiration.toFixed(0)
          : (notification.options.expiration.getTime() / 1000).toFixed(0)
    }

    if (notification.options.collapseId) {
      // @ts-ignore
      options.headers!['apns-collapse-id'] = notification.options.collapseId
    }

    const res = await fetch(url, options)

    return this._handleServerResponse(res, notification)
  }

  private async _handleServerResponse(res: Response, notification: Notification) {
    if (res.status === 200) {
      return notification
    }

    let json: any

    try {
      json = await res.json()
    } catch (err) {
      json = { reason: Errors.unknownError }
    }

    json.statusCode = res.status
    json.notification = notification

    this.emit(json.reason, json)
    this.emit(Errors.error, json)

    throw json
  }

  private async _getSigningToken(): Promise<string> {
    if (this._token && Date.now() - this._token.timestamp < RESET_TOKEN_INTERVAL_MS) {
      return this._token.value
    }

    const claims = {
      iss: this.team,
      iat: Math.floor(Date.now() / 1000)
    }

    const token = await new jose.SignJWT(claims)
      .setProtectedHeader({
        alg: SIGNING_ALGORITHM,
        kid: this.keyId
      })
      .sign(await jose.importPKCS8(this.signingKey, SIGNING_ALGORITHM))

    this._token = {
      value: token,
      timestamp: Date.now()
    }

    return token
  }

  private _resetSigningToken() {
    this._token = null
  }

  initToken (value: string): void {
    this._token = {
      value,
      timestamp: Date.now()
    }
  }

  async getToken() {
    return this._getSigningToken()
  }
}
