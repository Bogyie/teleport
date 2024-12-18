/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import websession from 'teleport/services/websession';
import 'whatwg-fetch';

import { MfaContextValue } from 'teleport/MFAContext/MFAContext';

import { MfaChallengeResponse } from '../mfa';
import { storageService } from '../storageService';

import parseError, { ApiError } from './parseError';

export const MFA_HEADER = 'Teleport-Mfa-Response';

let mfaContext: MfaContextValue;

const api = {
  setMfaContext(mfa: MfaContextValue) {
    mfaContext = mfa;
  },

  get(
    url: string,
    abortSignal?: AbortSignal,
    mfaResponse?: MfaChallengeResponse
  ) {
    return api.fetchJsonWithMfaAuthnRetry(
      url,
      { signal: abortSignal },
      mfaResponse
    );
  },

  post(url, data?, abortSignal?, mfaResponse?: MfaChallengeResponse) {
    return api.fetchJsonWithMfaAuthnRetry(
      url,
      {
        body: JSON.stringify(data),
        method: 'POST',
        signal: abortSignal,
      },
      mfaResponse
    );
  },

  postFormData(url, formData, mfaResponse?: MfaChallengeResponse) {
    if (formData instanceof FormData) {
      return api.fetchJsonWithMfaAuthnRetry(
        url,
        {
          body: formData,
          method: 'POST',
          // Overrides the default header from `defaultRequestOptions`.
          headers: {
            Accept: 'application/json',
            // Let the browser infer the content-type for FormData types
            // to set the correct boundary:
            // 1) https://developer.mozilla.org/en-US/docs/Web/API/FormData/Using_FormData_Objects#sending_files_using_a_formdata_object
            // 2) https://stackoverflow.com/a/64653976
          },
        },
        mfaResponse
      );
    }

    throw new Error('data for body is not a type of FormData');
  },

  delete(url, data?, mfaResponse?: MfaChallengeResponse) {
    return api.fetchJsonWithMfaAuthnRetry(
      url,
      {
        body: JSON.stringify(data),
        method: 'DELETE',
      },
      mfaResponse
    );
  },

  deleteWithHeaders(
    url,
    headers?: Record<string, string>,
    signal?,
    mfaResponse?: MfaChallengeResponse
  ) {
    return api.fetchJsonWithMfaAuthnRetry(
      url,
      {
        method: 'DELETE',
        headers,
        signal,
      },
      mfaResponse
    );
  },

  // TODO (avatus) add abort signal to this
  put(url, data, mfaResponse?: MfaChallengeResponse) {
    return api.fetchJsonWithMfaAuthnRetry(
      url,
      {
        body: JSON.stringify(data),
        method: 'PUT',
      },
      mfaResponse
    );
  },

  putWithHeaders(
    url,
    data,
    headers?: Record<string, string>,
    mfaResponse?: MfaChallengeResponse
  ) {
    return api.fetchJsonWithMfaAuthnRetry(
      url,
      {
        body: JSON.stringify(data),
        method: 'PUT',
        headers,
      },
      mfaResponse
    );
  },

  /**
   * fetchJsonWithMfaAuthnRetry calls on `api.fetch` and
   * processes the response.
   *
   * It returns the JSON data if it is a valid JSON and
   * there were no response errors.
   *
   * If a response had an error and it contained a MFA authn
   * required message, then a retry is attempted after a user
   * successfully re-authenticates with an MFA device.
   *
   * All other errors will be thrown.
   */
  async fetchJsonWithMfaAuthnRetry(
    url: string,
    customOptions: RequestInit,
    mfaResponse?: MfaChallengeResponse
  ): Promise<any> {
    const response = await api.fetch(url, customOptions, mfaResponse);

    let json;
    try {
      json = await response.json();
    } catch (err) {
      const message = response.ok
        ? err.message
        : `${response.status} - ${response.url}`;
      throw new ApiError(message, response, { cause: err });
    }

    if (response.ok) {
      return json;
    }

    /** This error can occur in the edge case where a role in the user's certificate was deleted during their session. */
    const isRoleNotFoundErr = isRoleNotFoundError(parseError(json));
    if (isRoleNotFoundErr) {
      websession.logoutWithoutSlo({
        /* Don't remember location after login, since they may no longer have access to the page they were on. */
        rememberLocation: false,
        /* Show "access changed" notice on login page. */
        withAccessChangedMessage: true,
      });
      return;
    }

    // Retry with MFA if we get an admin action missing MFA error.
    const isAdminActionMfaError = isAdminActionRequiresMfaError(
      parseError(json)
    );
    const shouldRetry = isAdminActionMfaError && !mfaResponse;
    if (!shouldRetry) {
      throw new ApiError(parseError(json), response, undefined, json.messages);
    }

    let mfaResponseForRetry;
    try {
      mfaResponseForRetry = await mfaContext.getAdminActionMfaResponse();
    } catch {
      throw new Error(
        'Failed to fetch MFA challenge. Please connect a registered hardware key and try again. If you do not have a hardware key registered, you can add one from your account settings page.'
      );
    }

    return api.fetchJsonWithMfaAuthnRetry(
      url,
      customOptions,
      mfaResponseForRetry
    );
  },

  /**
   * fetch calls upon native fetch with options and headers set
   * to default (or provided) values.
   *
   * @param customOptions is an optional RequestInit object.
   * It can be provided to either override some fields defined in
   * `defaultRequestOptions` or define new fields not in
   * `defaultRequestOptions`.
   *
   * customOptions gets shallowly merged with `defaultRequestOptions` where
   * inner objects do not get merged if overrided.
   *
   * Example with an example customOption:
   * {
   *  body: formData,
   *  method: 'POST',
   *  headers: {
   *    Accept: 'application/json',
   *  }
   * }
   *
   * 'headers' is a field also defined in `defaultRequestOptions`, because of
   * shallow merging, the customOption.headers will get completely overrided.
   * After merge:
   *
   * {
   *  body: formData,
   *  method: 'POST',
   *  headers: {
   *    Accept: 'application/json',
   *  },
   *  credentials: 'same-origin',
   *  mode: 'same-origin',
   *  cache: 'no-store'
   * }
   *
   * If customOptions field is not provided, only fields defined in
   * `defaultRequestOptions` will be used.
   *
   * @param mfaResponse if defined (eg: `fetchJsonWithMfaAuthnRetry`)
   * will add a custom MFA header field that will hold the mfaResponse.
   */
  fetch(
    url: string,
    customOptions: RequestInit = {},
    mfaResponse?: MfaChallengeResponse
  ) {
    url = window.location.origin + url;
    const options = {
      ...defaultRequestOptions,
      ...customOptions,
    };

    options.headers = {
      ...options.headers,
      ...getAuthHeaders(),
    };

    if (mfaResponse) {
      options.headers[MFA_HEADER] = JSON.stringify({
        ...mfaResponse,
        // TODO(Joerger): DELETE IN v19.0.0.
        // We include webauthnAssertionResponse for backwards compatibility.
        webauthnAssertionResponse: mfaResponse.webauthn_response,
      });
    }

    // native call
    return fetch(url, options);
  },
};

export const defaultRequestOptions: RequestInit = {
  credentials: 'same-origin',
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json; charset=utf-8',
  },
  mode: 'same-origin',
  cache: 'no-store',
};

export function getAuthHeaders() {
  const accessToken = getAccessToken();
  const csrfToken = getXCSRFToken();
  return {
    'X-CSRF-Token': csrfToken,
    Authorization: `Bearer ${accessToken}`,
  };
}

export function getNoCacheHeaders() {
  return {
    'cache-control': 'max-age=0',
    expires: '0',
    pragma: 'no-cache',
  };
}

export const getXCSRFToken = () => {
  const metaTag = document.querySelector(
    '[name=grv_csrf_token]'
  ) as HTMLMetaElement;
  return metaTag ? metaTag.content : '';
};

export function getAccessToken() {
  return storageService.getBearerToken()?.accessToken;
}

export function getHostName() {
  return location.hostname + (location.port ? ':' + location.port : '');
}

function isAdminActionRequiresMfaError(errMessage) {
  return errMessage.includes(
    'admin-level API request requires MFA verification'
  );
}

/** isRoleNotFoundError returns true if the error message is due to a role not being found. */
export function isRoleNotFoundError(errMessage: string): boolean {
  // This error message format should be kept in sync with the NotFound error message returned in lib/services/local/access.GetRole
  return /role \S+ is not found/.test(errMessage);
}

export default api;
