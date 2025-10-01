import { SetMetadata } from '@nestjs/common';

const SKIP_AT_KEY = 'skip-at-check';
const SkipAtCheck = () => SetMetadata(SKIP_AT_KEY, true);

export { SKIP_AT_KEY, SkipAtCheck };
