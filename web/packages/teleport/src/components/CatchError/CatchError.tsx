/**
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

import { Failed } from 'design/CardError';
import React from 'react';
import Logger from 'shared/libs/logger';

const logger = Logger.create('components/CatchError');

export class CatchError extends React.PureComponent<Props, State> {
  state: State = { error: null };

  private retry = () => {
    this.setState({ error: null });
    this.props.onRetry?.();
  };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(err) {
    logger.error('render', err);
  }

  render() {
    if (this.state.error) {
      if (this.props.fallbackFn) {
        return this.props.fallbackFn({
          error: this.state.error,
          retry: this.retry,
        });
      }

      // Default fallback UI.
      return (
        <Failed alignSelf={'baseline'} message={this.state.error.message} />
      );
    }

    return this.props.children;
  }
}

type FallbackFnProp = {
  error: Error;
  retry(): void;
};

type State = {
  error: Error;
};

type Props = {
  children: React.ReactNode;
  onRetry?(): void;
  fallbackFn?(props: FallbackFnProp): React.ReactNode;
};
