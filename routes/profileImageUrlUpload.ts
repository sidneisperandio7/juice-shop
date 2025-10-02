/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      // SSRF protection: Only allow URLs from known safe domains
      const ALLOWED_IMAGE_HOSTS = [
        'imgur.com',
        'i.imgur.com',
        'images.unsplash.com',
        'cdn.pixabay.com'
        // Add other legitimate image hosts as needed
      ]
      function isSafeImageUrl(imageUrl) {
        try {
          const parsedUrl = new URL(imageUrl)
          // Enforce http(s) protocol
          if (!['http:', 'https:'].includes(parsedUrl.protocol)) return false
          // Host domain should be in the allow-list and not a localhost or private IP
          const hostname = parsedUrl.hostname
          // Check for localhost and local IPs
          if (
            hostname === 'localhost' ||
            hostname === '127.0.0.1' ||
            hostname === '::1' ||
            /^10\./.test(hostname) ||
            /^192\.168\./.test(hostname) ||
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname) ||
            /^169\.254\./.test(hostname)
          ) return false
          // Check if the host is in the allow-list (allow subdomains)
          if (ALLOWED_IMAGE_HOSTS.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
            return true
          }
          return false
        } catch (err) {
          return false
        }
      }
      if (loggedInUser) {
        try {
          if (!isSafeImageUrl(url)) {
            res.status(400).send({ error: 'Invalid image URL. Only trusted image hosts are allowed.' })
            return
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
